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

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Write-Host needed for Azure DevOps logging')]
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

$excludeAvailableAsResource = @('*UniqueId','*IsSingleInstance','NonNodeData.Environment.Tokens*')
$mergeKeys = @('NodeName', 'Identity', 'Id', 'UniqueId', 'SettingDefinitionId')
$sortKeys = @('Priority')

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
Write-Log -Object '-----------------------------------------------------------------------'
Write-Log -Object 'Reading and merging Mandatory configuration file(s): Mandatory*.psd1'
Write-Log -Object '-----------------------------------------------------------------------'
[System.Array]$mandatoryConfigFiles = Get-ChildItem -Path (Join-Path -Path $dataFilesFolder -ChildPath 'Templates\Mandatory') -Filter 'Mandatory*.psd1'
Write-Log -Object "- Found $($mandatoryConfigFiles.Count) Mandatory configuration file(s)"
Write-Log -Object 'Processing Mandatory configuration file(s)'
$c = 0
foreach ($mandatoryConfigFile in $mandatoryConfigFiles)
{
    if ($c -eq 0)
    {
        Write-Log -Object '----------------------------------------------------'
        Write-Log -Object "Importing file: $($mandatoryConfigFile.Name)"
        Write-Log -Object '----------------------------------------------------'
        $mandatoryConfig = Import-PSDataFile $mandatoryConfigFile.FullName

        Write-Log -Object '  Testing if data adheres to the data schema'
        $mandatoryTestResults = Test-M365DSCPowershellDataFile -Test 'TypeValue' -InputObject $mandatoryConfig -ExcludeAvailableAsResource $excludeAvailableAsResource -PesterOutputObject
        if ($mandatoryTestResults.Result -ne 'Passed')
        {
            Write-Log -Object "  [ERROR] Data errors found in the Mandatory configuration data file: $($mandatoryConfigFile.Name)" -Failure
            $qaCheckErrors = $true
        }
        else
        {
            Write-Log -Object '  All tests have passed!'
        }

        $mandatoryConfigNode = Get-Node -InputObject $mandatoryConfig
    }
    else
    {
        Write-Log -Object '----------------------------------------------------'
        Write-Log -Object "Merging file: $($mandatoryConfigFile.Name)"
        Write-Log -Object '----------------------------------------------------'
        $mandatoryConfigNextFragment = Import-PSDataFile $mandatoryConfigFile.Fullname
        
        Write-Log -Object '  Testing if data adheres to the data schema'
        $mandatoryTestResults = $null
        $mandatoryTestResults = Test-M365DSCPowershellDataFile -Test 'TypeValue' -InputObject $mandatoryConfigNextFragment -ExcludeAvailableAsResource $excludeAvailableAsResource -PesterOutputObject
        if ($mandatoryTestResults.Result -ne 'Passed')
        {
            Write-Log -Object "  [ERROR] Data errors found in the Mandatory configuration data file: $($mandatoryConfigFile.Name)" -Failure
            $qaCheckErrors = $true
        }
        else
        {
            Write-Log -Object '  All tests have passed!'
        }

        $mandatoryConfigNextFragmentNode = Get-Node -InputObject $mandatoryConfigNextFragment

        Write-Log -Object '  Merging files'
        $mandatoryConfigNode = Merge-ObjectGraph -InputObject $mandatoryConfigNextFragmentNode -Template $mandatoryConfigNode -PrimaryKey $mergeKeys
    }
    $c++
}
Write-Log -Object ' '

Write-Log -Object '----------------------------------------------------------------'
Write-Log -Object 'Reading and merging Basic configuration file(s): Basic*.psd1'
Write-Log -Object '----------------------------------------------------------------'
[System.Array]$basicConfigFiles = Get-ChildItem -Path (Join-Path -Path $dataFilesFolder -ChildPath 'Templates\Basic') -Filter 'Basic*.psd1'
Write-Log -Object "- Found $($basicConfigFiles.Count) Basic configuration file(s)"
Write-Log -Object 'Processing Basic configuration file(s)'
$c = 0
foreach ($basicConfigFile in $basicConfigFiles)
{
    if ($c -eq 0)
    {
        Write-Log -Object '----------------------------------------------------'
        Write-Log -Object "Importing file: $($basicConfigFile.Name)"
        Write-Log -Object '----------------------------------------------------'
        $basicConfig = Import-PSDataFile $basicConfigFile.FullName

        Write-Log -Object '  Testing if data adheres to the data schema'
        $basicTestResults = Test-M365DSCPowershellDataFile -Test 'TypeValue' -InputObject $basicConfig -ExcludeAvailableAsResource $excludeAvailableAsResource -PesterOutputObject
        if ($basicTestResults.Result -ne 'Passed')
        {
            Write-Log -Object "  [ERROR] Data errors found in the Basic configuration data file: $($basicConfigFile.Name)" -Failure
            $qaCheckErrors = $true
        }
        else
        {
            Write-Log -Object '  All tests have passed!'
        }

        $basicConfigNode = Get-Node -InputObject $basicConfig
    }
    else
    {
        Write-Log -Object '----------------------------------------------------'
        Write-Log -Object "Merging file: $($basicConfigFile.Name)"
        Write-Log -Object '----------------------------------------------------'
        $basicConfigNextFragment = Import-PSDataFile $basicConfigFile.FullName

        Write-Log -Object '  Testing if data adheres to the data schema'
        $basicTestResults = $null
        $basicTestResults = Test-M365DSCPowershellDataFile -Test 'TypeValue' -InputObject $basicConfigNextFragment -ExcludeAvailableAsResource $excludeAvailableAsResource -PesterOutputObject
        if ($basicTestResults.Result -ne 'Passed')
        {
            Write-Log -Object "  [ERROR] Data errors found in the Basic configuration data file: $($basicConfigFile.Name)" -Failure
            $qaCheckErrors = $true
        }
        else
        {
            Write-Log -Object '  All tests have passed!'
        }

        $basicConfigNextFragmentNode = Get-Node -InputObject $basicConfigNextFragment

        Write-Log -Object 'Merging files'
        $basicConfigNode = Merge-ObjectGraph -InputObject $basicConfigNextFragmentNode -Template $basicConfigNode -PrimaryKey $mergeKeys
    }
    $c++
}

Write-Log -Object 'Testing if Mandatory data is present in Basic data'
$mandatoryTestResults = Test-M365DSCPowershellDataFile -InputObject $basicConfigNode -MandatoryObject $mandatoryConfigNode -Test 'Mandatory' -MandatoryAction 'Present' -PesterOutputObject

if ($mandatoryTestResults.Result -ne 'Passed')
{
    Write-Log -Object '  [ERROR] Basic configuration does not contain Mandatory settings!' -Failure
    $qaCheckErrors = $true
}
else
{
    Write-Log -Object '  All tests have passed!'
}
Write-Log -Object ' '

Write-Log -Object '---------------------------------------------------------------------------------------------------------'
Write-Log -Object "Reading and merging environment-specific configuration file(s): <EnvName>$($configFileSeparator)*.psd1"
Write-Log -Object '---------------------------------------------------------------------------------------------------------'
[System.Array]$dataFiles = Get-ChildItem -Path (Join-Path -Path $dataFilesFolder -ChildPath 'Environments') -Filter '*.psd1' -Recurse
[System.Array]$environments = $dataFiles | Select-Object @{Label = 'Environment'; Expression = { ($_.BaseName -split $configFileSeparator)[0] } } | Sort-Object -Unique -Property Environment
Write-Log -Object "Found $($dataFiles.Count) data file(s) for $($environments.Count) environment(s)"
$envsConfig = @()
foreach ($environment in $environments.Environment)
{
    Write-Log -Object '----------------------------------------------------------'
    Write-Log -Object "Processing data files for environment '$environment'"
    Write-Log -Object '----------------------------------------------------------'
    Write-Log -Object ' '
    [System.Array]$envDataFiles = $dataFiles | Where-Object { $_.BaseName -match "^($environment$|$environment$configFileSeparator)" }
    $c = 0
    foreach ($envDataFile in $envDataFiles)
    {
        if ($c -eq 0)
        {
            Write-Log -Object '-------------------------------------------'
            Write-Log -Object "Importing file: $($envDataFile.Name)"
            Write-Log -Object '-------------------------------------------'
            $envConfig = Import-PSDataFile $envDataFile.FullName
        
            Write-Log -Object '  Testing if data adheres to the data schema'
            $envTestResults = Test-M365DSCPowershellDataFile -Test 'TypeValue' -InputObject $envConfig -ExcludeAvailableAsResource $excludeAvailableAsResource -PesterOutputObject
            if ($envTestResults.Result -ne 'Passed')
            {
                Write-Log -Object "  [ERROR] Data errors found in the Environment configuration data file: $($envDataFile.Name)" -Failure
                $qaCheckErrors = $true
            }
            else
            {
                Write-Log -Object '  All tests have passed!'
            }

            $envConfigNode = Get-Node -InputObject $envConfig
        }
        else
        {
            Write-Log -Object '-------------------------------------------'
            Write-Log -Object "Merging file: $($envDataFile.Name)"
            Write-Log -Object '-------------------------------------------'
            $envConfigNextFragment = Import-PSDataFile $envDataFile.FullName
        
            Write-Log -Object '  Testing if data adheres to the data schema'
            $envTestResults = $null
            $envTestResults = Test-M365DSCPowershellDataFile -Test 'TypeValue' -InputObject $envConfigNextFragment -ExcludeAvailableAsResource $excludeAvailableAsResource -PesterOutputObject
            if ($envTestResults.Result -ne 'Passed')
            {
                Write-Log -Object "  [ERROR] Data errors found in the Environment configuration data file: $($envDataFile.Name)" -Failure
                $qaCheckErrors = $true
            }
            else
            {
                Write-Log -Object '  All tests have passed!'
            }

            $envConfigNextFragmentNode = Get-Node -InputObject $envConfigNextFragment

            Write-Log -Object '  Merging files'
            $envConfigNode = Merge-ObjectGraph -InputObject $envConfigNextFragmentNode -Template $envConfigNode -PrimaryKey $mergeKeys
        }
        $c++
    }
    $certPath = Join-Path -Path $rootDirectoryCICD -ChildPath $envConfigNode.AllNodes[0].CertificateFile.TrimStart('.\')
    $envConfigNode.AllNodes[0].CertificateFile = $certPath

    Write-Log -Object 'Testing if Mandatory data is NOT present in Environment data'
    $mandatoryTestResults = Test-M365DSCPowershellDataFile -InputObject $envConfigNode -MandatoryObject $mandatoryConfigNode -Test 'Mandatory' -MandatoryAction 'Absent' -PesterOutputObject

    if ($mandatoryTestResults.Result -ne 'Passed')
    {
        Write-Log -Object "  [ERROR] Environment configuration for '$environment' contains Mandatory settings, which is not allowed!" -Failure
        $qaCheckErrors = $true
    }
    else
    {
        Write-Log -Object '  All tests have passed!'
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
$count = $envsConfig.Count
$current = 1
foreach ($environment in $envsConfig)
{
    Write-Log -Object ' '
    Write-Log -Object '---------------------------------------------------------------------'
    Write-Log -Object "Processing environment [$current/$count]: $($environment.Name)"
    Write-Log -Object '---------------------------------------------------------------------'

    $outputPathDataFile = Join-Path -Path $outputFolder -ChildPath $environment.Name
    if ((Test-Path -Path $outputPathDataFile) -eq $false)
    {
        $null = New-Item -Path $outputPathDataFile -ItemType Directory
    }

    Write-Log -Object ' '
    Write-Log -Object 'Merging basic config with environment-specific config'
    $mergedConfigDataNode = Merge-ObjectGraph -InputObject $environment.Config -Template $basicConfigNode -PrimaryKey $mergeKeys

    Write-Log -Object 'Exporting Original ConfigData to file'
    Write-Log -Object "  Sorting and exporting data on keys: $($sortKeys -join ", ")"
    $psdStringData = $mergedConfigDataNode | Sort-ObjectGraph -PrimaryKey $sortKeys -MaxDepth 20 | ConvertTo-Expression
    $originalPsdPath = Join-Path -Path $outputPathDataFile -ChildPath "$($environment.Name)_Original.psd1"
    Set-Content -Path $originalPsdPath -Value $psdStringData

    # Replace Tokens in the ConfigData
    Write-Log -Object ' '
    Write-Log -Object 'Replacing tokens in ConfigData'
    $tokens = $mergedConfigDataNode.NonNodeData.Environment.Tokens
    $Obj_Result_Serialized = [System.Management.Automation.PSSerializer]::Serialize($mergedConfigDataNode)
    foreach ($token in $tokens.GetEnumerator())
    {
        '- Token Replaced:  {0}  <-  "{1}"' -f $token.name.PadRight(20, ' '), $token.value | Write-Log
        $Obj_Result_Serialized = $Obj_Result_Serialized -replace "{{$($token.name)}}", $token.value
    }
    $mergedConfigDataNode = [System.Management.Automation.PSSerializer]::Deserialize($Obj_Result_Serialized)

    Write-Log -Object 'Exporting Tokenized ConfigData to file'
    $psdStringData = $mergedConfigDataNode | ConvertTo-Expression
    $finalPsdPath = Join-Path -Path $outputPathDataFile -ChildPath "$($environment.Name).psd1"
    Set-Content -Path $finalPsdPath -Value $psdStringData
    Write-Log -Object ' '

    $mergedConfigDataNode = Import-PSDataFile -Path (Resolve-Path -Path $finalPsdPath).Path

    Write-Log -Object 'Testing for presence of all Required parameters in merged configuration data'
    $qaTestResults = Test-M365DSCPowershellDataFile -InputObject $mergedConfigDataNode -Test 'Required' -ExcludeAvailableAsResource $excludeAvailableAsResource -PesterOutputObject
    Write-Log -Object ' '

    if ($qaTestResults.Result -ne 'Passed')
    {
        Write-Log -Object '  [ERROR] Data errors found in compiled configuration data files!' -Failure
        $qaCheckErrors = $true
    }
    else
    {
        Write-Log -Object '  All tests have passed!'
    }
    $current++
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
