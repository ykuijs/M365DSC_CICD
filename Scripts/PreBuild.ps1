using module ObjectGraphTools

#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Compiles the DSC MOF files, based on the Basic and Environment-specific data files.

.DESCRIPTION
    This script compiles the DSC MOF files and it uses the Basic and Environment-specific
    data files as input data. The script also performs quality checks on the data files,
    to make sure the data is correct and valid.

.EXAMPLE
    .\build.ps1
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
[CmdletBinding()]
param
()

######## SCRIPT VARIABLES ########
$configFileSeparator = '#'
$workingDirectoryCICD = $PSScriptRoot
$rootDirectoryCICD = Split-Path -Path $PSScriptRoot
$workingDirectoryData = Join-Path -Path $workingDirectoryCICD -ChildPath '..\..\Data' -Resolve
$outputFolder = Join-Path -Path $workingDirectoryCICD -ChildPath '..\..\Output'
$dataFilesFolder = Join-Path -Path $workingDirectoryData -ChildPath '\DataFiles'
$testsFolder = Join-Path -Path $workingDirectoryCICD -ChildPath '..\Tests' -Resolve
$qaTestPath = Join-Path -Path $testsFolder -ChildPath 'Run-QATests.ps1' -Resolve
$qaCheckErrors = $false

######## START SCRIPT ########

try
{
    Import-Module -Name (Join-Path -Path $workingDirectoryCICD -ChildPath 'SupportFunctions.psm1') -ErrorAction Stop
}
catch
{
    Write-Host "ERROR: Could not load library 'SupportFunctions.psm1'. $($_.Exception.Message.Trim('.')). Exiting." -ForegroundColor Red
    exit -1
}

Write-Log -Object '*********************************************************'
Write-Log -Object '*   Starting Microsoft365DSC PreBuild steps             *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
Write-Log -Object "Switching to path: $workingDirectoryCICD"
Set-Location -Path $workingDirectoryCICD

# Quality checks
Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Running quality checks '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
$qaTestResults = & $qaTestPath
if ($qaTestResults.Result -ne 'Passed')
{
    Write-Log -Object "[ERROR] $($qaTestResults.FailedCount) QA checks failed! Exiting!"
    Write-Host '##vso[task.complete result=Failed;]Failed'
    exit -1
}

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Preparing MOF compilation'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '

Write-Log -Object "Preparing OutputFolder '$outputFolder'"
if ((Test-Path -Path $outputFolder))
{
    Write-Log -Object 'OutputFolder already exists. Cleaning up...'
    Remove-Item -Path $outputFolder -Recurse -Confirm:$false
}
$null = New-Item -Path $outputFolder -ItemType Directory

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Reading Microsoft365DSC configuration files'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
Write-Log -Object 'Reading and merging Mandatory configuration file(s): Mandatory*.psd1'
[System.Array]$mandatoryConfigFiles = Get-ChildItem -Path (Join-Path -Path $dataFilesFolder -ChildPath 'Templates\Mandatory') -Filter 'Mandatory*.psd1'
Write-Log -Object "- Found $($mandatoryConfigFiles.Count) Mandatory configuration file(s)"
Write-Log -Object 'Processing Mandatory configuration file(s)'
$c = 0
foreach ($mandatoryConfigFile in $mandatoryConfigFiles)
{
    if ($c -eq 0)
    {
        Write-Log -Object "Importing file: $($mandatoryConfigFile.Name)"
        $mandatoryConfig = Import-PSDataFile $mandatoryConfigFile.FullName
        $mandatoryConfigNode = Get-Node -InputObject $mandatoryConfig
    }
    else
    {
        Write-Log -Object "Merging file: $($mandatoryConfigFile.Name)"
        $mandatoryConfigNextFragment = Import-PSDataFile $mandatoryConfigFile.Fullname
        $mandatoryConfigNextFragmentNode = Get-Node -InputObject $mandatoryConfigNextFragment
        $mandatoryConfigNode = Merge-ObjectGraph -InputObject $mandatoryConfigNextFragmentNode -Template $mandatoryConfigNode -PrimaryKey 'NodeName', 'Id', 'Identity', 'UniqueId'
    }
    $c++
}
Write-Log -Object ' '

Write-Log -Object 'Reading and merging Basic configuration file(s): Basic*.psd1'
[System.Array]$basicConfigFiles = Get-ChildItem -Path (Join-Path -Path $dataFilesFolder -ChildPath 'Templates\Basic') -Filter 'Basic*.psd1'
Write-Log -Object "- Found $($basicConfigFiles.Count) Basic configuration file(s)"
Write-Log -Object 'Processing Basic configuration file(s)'
$c = 0
foreach ($basicConfigFile in $basicConfigFiles)
{
    if ($c -eq 0)
    {
        Write-Log -Object "Importing file: $($basicConfigFile.Name)"
        $basicConfig = Import-PSDataFile $basicConfigFile.FullName
        $basicConfigNode = Get-Node -InputObject $basicConfig
    }
    else
    {
        Write-Log -Object "Merging file: $($basicConfigFile.Name)"
        $basicConfigNextFragment = Import-PSDataFile $basicConfigFile.FullName
        $basicConfigNextFragmentNode = Get-Node -InputObject $basicConfigNextFragment
        $basicConfigNode = Merge-ObjectGraph -InputObject $basicConfigNextFragmentNode -Template $basicConfigNode -PrimaryKey 'NodeName', 'Id', 'Identity', 'UniqueId'
    }
    $c++
}
Write-Log -Object ' '

Write-Log -Object "Testing if Mandatory data is present in Basic data"
$mandatoryTestResults = Test-M365MandatoryPowershellDataFile -InputObject $basicConfigNode -MandatoryObject $mandatoryConfigNode

if ($mandatoryTestResults.Result -ne 'Passed')
{
    Write-Log -Object '[ERROR] Basic configuration does not contain Mandatory settings!' -Failure
    $qaCheckErrors = $true
}
Write-Log -Object ' '

Write-Log -Object "Reading and merging environment-specific configuration file(s): <EnvName>$($configFileSeparator)*.psd1"
[System.Array]$dataFiles = Get-ChildItem -Path (Join-Path -Path $dataFilesFolder -ChildPath 'Environments') -Filter '*.psd1' -Recurse
[System.Array]$environments = $dataFiles | Select-Object @{Label = 'Environment'; Expression = { ($_.BaseName -split $configFileSeparator)[0] } } | Sort-Object -Unique -Property Environment
Write-Log -Object "Found $($dataFiles.Count) data file(s) for $($environments.Count) environment(s)"
$envsConfig = @()
foreach ($environment in $environments.Environment)
{
    Write-Log -Object "Processing data files for environment '$environment'"
    [System.Array]$envDataFiles = $dataFiles | Where-Object { $_.BaseName -match "^($environment$|$environment$configFileSeparator)" }
    $c = 0
    foreach ($envDataFile in $envDataFiles)
    {
        if ($c -eq 0)
        {
            Write-Log -Object "Importing file: $($envDataFile.Name)"
            $envConfig = Import-PSDataFile $envDataFile.FullName
            $envConfigNode = Get-Node -InputObject $envConfig
        }
        else
        {
            Write-Log -Object "Merging file: $($envDataFile.Name)"
            $envConfigNextFragment = Import-PSDataFile $envDataFile.FullName
            $envConfigNextFragmentNode = Get-Node -InputObject $envConfigNextFragment
            $envConfigNode = Merge-ObjectGraph -InputObject $envConfigNextFragmentNode -Template $envConfigNode -PrimaryKey 'NodeName', 'Id', 'Identity', 'UniqueId'
        }
        $c++
    }
    $certPath = Join-Path -Path $rootDirectoryCICD -ChildPath $envConfigNode.AllNodes[0].CertificateFile.TrimStart('.\')
    $envConfigNode.AllNodes[0].CertificateFile = $certPath

    Write-Log -Object "Testing if Mandatory data is present in Environment data"
    $mandatoryTestResults = Test-M365MandatoryPowershellDataFile -InputObject $envConfigNode -MandatoryObject $mandatoryConfigNode -NotAllowedMandatory

    if ($mandatoryTestResults.Result -ne 'Passed')
    {
        Write-Log -Object '[ERROR] Environment configuration for '$environment' contains Mandatory settings, which is not allowed!' -Failure
        $qaCheckErrors = $true
    }
    Write-Log -Object ' '

    $envsConfig += @{
        Name   = $environment
        Config = $envConfigNode
    }
    Write-Log -Object ' '
}

Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Starting Basic/Tenant merge, Tokenizing and QA testing'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
foreach ($environment in $envsConfig)
{
    Write-Log -Object "Processing environment: $($environment.Name)"

    $outputPathDataFile = Join-Path -Path $outputFolder -ChildPath $environment.Name
    if ((Test-Path -Path $outputPathDataFile) -eq $false)
    {
        $null = New-Item -Path $outputPathDataFile -ItemType Directory
    }

    Write-Log -Object ' '
    Write-Log -Object 'Merging basic config with environment-specific config'
    $mergedConfigDataNode = Merge-ObjectGraph -InputObject $environment.Config -Template $basicConfigNode -PrimaryKey 'NodeName', 'Identity', 'Id', 'UniqueId'

    $psdStringData = $mergedConfigDataNode | Sort-ObjectGraph -PrimaryKey 'NodeName', 'Identity', 'Id', 'UniqueId', 'Priority' -MaxDepth 20 | ConvertTo-Expression
    $originalPsdPath = Join-Path -Path $outputPathDataFile -ChildPath "$($environment.Name)_Original.psd1"
    Set-Content -Path $originalPsdPath -Value $psdStringData

    # Replace Tokens in the ConfigData
    Write-Log -Object ' '
    Write-Log -Object 'Replacing tokens in ConfigData'
    $tokens = $mergedConfigDataNode.NonNodeData.Environment.Tokens
    $Obj_Result_Serialized = [System.Management.Automation.PSSerializer]::Serialize($mergedConfigDataNode)
    foreach ($token in $tokens.GetEnumerator())
    {
        '- Token Replaced:  {0}  <-  "{1}"' -f $token.name.PadRight(20, ' '), $token.value | Write-log
        $Obj_Result_Serialized = $Obj_Result_Serialized -replace "{{$($token.name)}}", $token.value
    }
    $mergedConfigDataNode = [System.Management.Automation.PSSerializer]::Deserialize($Obj_Result_Serialized)

    $psdStringData = $mergedConfigDataNode | Sort-ObjectGraph -PrimaryKey 'NodeName', 'Identity', 'Id', 'UniqueId', 'Priority' -MaxDepth 20 | ConvertTo-Expression
    $finalPsdPath = Join-Path -Path $outputPathDataFile -ChildPath "$($environment.Name).psd1"
    Set-Content -Path $finalPsdPath -Value $psdStringData

    $mergedConfigDataNode = Import-PSDataFile -Path (Resolve-Path -Path $finalPsdPath).Path

    Write-Log -Object 'Testing merged configuration data'
    $qaTestResults = Test-M365PowershellDataFile -InputObject $mergedConfigDataNode -Exclude_Required IsSingleInstance, UniqueId -Exclude_AvailableAsResource IsSingleInstance, UniqueId
    Write-Log -Object ' '

    if ($qaTestResults.Result -ne 'Passed')
    {
        Write-Log -Object '[ERROR] Data errors found in compiled configuration data files!' -Failure
        $qaCheckErrors = $true
    }
}

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
if ($qaCheckErrors)
{
    Write-Log -Object ' RESULT: PreBuild script encountered errors!' -Failure
    Write-Host '##vso[task.complete result=Failed;]Failed'
}
else
{
    Write-Log -Object ' RESULT: PreBuild script completed successfully!'
}
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
Write-Log -Object '*********************************************************'
Write-Log -Object '*   Finished Microsoft365DSC PreBuild steps             *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
