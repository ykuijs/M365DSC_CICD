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
#Import-Module -Name ObjectGraphTools -RequiredVersion 0.0.20 -Force
$dscScriptName = 'M365Configuration.ps1'
$configFileSeparator = '#'
$workingDirectoryCICD = $PSScriptRoot
$rootDirectoryCICD = Split-Path -Path $PSScriptRoot
$workingDirectoryData = Join-Path -Path $workingDirectoryCICD -ChildPath '..\..\Data' -Resolve
$outputFolder = Join-Path -Path $workingDirectoryCICD -ChildPath '..\..\Output'
$dataFilesFolder = Join-Path -Path $workingDirectoryData -ChildPath '\DataFiles'

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
Write-Log -Object '*   Starting Microsoft365DSC Configuration Compilation  *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
Write-Log -Object "Switching to path: $workingDirectoryCICD"
Set-Location -Path $workingDirectoryCICD

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Preparing MOF compilation'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '

Write-Log -Object "Loading DSC Main configuration '$dscScriptName'"
. (Join-Path -Path $workingDirectoryCICD -ChildPath $dscScriptName)

Write-Log -Object "Checking OutputFolder '$outputFolder'"
if ((Test-Path -Path $outputFolder) -eq $false)
{
    $null = New-Item -Path $outputFolder -ItemType Directory
}

Write-Log -Object 'Copying deployment scripts to OutputFolder'
Copy-Item -Path (Join-Path -Path $rootDirectoryCICD -ChildPath 'DscResources.psd1') -Destination $outputFolder
Copy-Item -Path (Join-Path -Path $rootDirectoryCICD -ChildPath 'PsExec.exe') -Destination $outputFolder
Copy-Item -Path 'deploy.ps1' -Destination $outputFolder
Copy-Item -Path 'supportfunctions.psm1' -Destination $outputFolder
Copy-Item -Path 'checkdsccompliance.ps1' -Destination $outputFolder

Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Starting MOF compilation'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
[System.Array]$dataFiles = Get-ChildItem -Path (Join-Path -Path $dataFilesFolder -ChildPath 'Environments') -Filter '*.psd1' -Recurse
[System.Array]$environments = $dataFiles | Select-Object @{Label = 'Name'; Expression = { ($_.BaseName -split $configFileSeparator)[0] } } | Sort-Object -Unique -Property Name

foreach ($environment in $environments)
{
    Write-Log -Object "Processing environment: $($environment.Name)"

    $outputPathDataFile = Join-Path -Path $outputFolder -ChildPath $environment.Name
    if ((Test-Path -Path $outputPathDataFile) -eq $false)
    {
        $null = New-Item -Path $outputPathDataFile -ItemType Directory
    }

    $finalPsdPath = Join-Path -Path $outputPathDataFile -ChildPath "$($environment.Name).psd1"
    $mergedConfigDataNode = Import-PSDataFile -Path (Resolve-Path -Path $finalPsdPath).Path

    Write-Log -Object "Generating MOF file for environment '$($environment.Name)'"
    try
    {
        $Error.Clear()
        $compileError = $false
        $null = M365Configuration -ConfigurationData $mergedConfigDataNode -OutputPath $outputPathDataFile
    }
    catch
    {
        Write-Log -Object '[ERROR] Error occurred during MOF compilation' -Failure
        Write-Log -Object "Error: $($_.Exception.Message)" -Failure
        $compileError = $true
    }
    finally
    {
        if ($Error.Count -gt 0)
        {
            $count = 1
            $Error.Reverse()
            foreach ($err in $Error)
            {
                Write-Log -Object ("[{1}] Error message: {0}" -f $err.Exception.Message, $count.ToString('000')) -Failure
                Write-Log -Object ("[{1}] StackTrace: {0}" -f ($err.ScriptStackTrace -replace "\n", " | "), $count.ToString('000')) -Failure
                $count++
            }
            $compileError = $true
        }
    }
    Write-Log -Object ' '
}

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
if ($compileError)
{
    Write-Log -Object ' RESULT: Build script encountered errors!' -Failure
    Write-Host '##vso[task.complete result=Failed;]Failed'
}
else
{
    Write-Log -Object ' RESULT: Build script completed successfully!'
}
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
Write-Log -Object '*********************************************************'
Write-Log -Object '*   Finished Microsoft365DSC Configuration Compilation  *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
