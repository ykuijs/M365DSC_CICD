#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Downloads and installs all required modules to the local machine.

.DESCRIPTION
    This script downloads and installs all required modules to the local machine, including the prepared Microsoft365DSC package from an
    Azure Blob Storage. This is required in the deployment pipeline.

.PARAMETER DeployM365Prerequisites
    If specified, the script will also deploy the required Microsoft365DSC modules from an Azure Blob Storage.

.EXAMPLE
    .\DeployModules.ps1

.EXAMPLE
    .\DeployModules.ps1 -DeployM365Prerequisites
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
[CmdletBinding()]
param
(
    [Parameter()]
    [Switch]
    $DeployM365Prerequisites
)

######## SCRIPT VARIABLES ########

$workingDirectoryCICD = $PSScriptRoot
$rootDirectoryCICD = Split-Path -Path $workingDirectoryCICD

if ($DeployM365Prerequisites)
{
    # Deploy phase
    $workingDirectoryData = Join-Path -Path $rootDirectoryCICD -ChildPath '..\..\Build MOF\DeployPackage' -Resolve
    $prerequisitesPath = Join-Path -Path $workingDirectoryData -ChildPath 'DscResources.psd1' -Resolve
}
else
{
    # Build phase
    $prerequisitesPath = Join-Path -Path $rootDirectoryCICD -ChildPath 'DscResources.psd1' -Resolve
}

$targetModulesPath = 'C:\Program Files\WindowsPowerShell\Modules'

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

try
{
    Import-Module -Name (Join-Path -Path $workingDirectoryCICD -ChildPath 'ModuleFast') -ErrorAction Stop
}
catch
{
    Write-Host "ERROR: Could not load library 'ModuleFast' ($($_.Exception.Message.Trim('.'))). Exiting." -ForegroundColor Red
    exit -1
}


Write-Log -Object '*********************************************************'
Write-Log -Object '*  Starting Deployment of M365 DSC Module Dependencies  *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
Write-Log -Object "Switching to path: $workingDirectoryCICD"
Set-Location -Path $workingDirectoryCICD

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Checking for presence of Microsoft365DSC module'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
$reqVersion = Install-DSCModule -TargetPath $targetModulesPath -PrerequisitesPath $prerequisitesPath

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Initializing PowerShell Gallery'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
Initialize-PSGallery

Write-Log -Object ' '
Write-Log -Object '-----------------------------------------------------------------------'
Write-Log -Object ' Installing generic modules from PSGallery or a custom NuGet repository'
Write-Log -Object '-----------------------------------------------------------------------'
Write-Log -Object ' '
Install-GenericModules -TargetPath $targetModulesPath -PrerequisitesPath $prerequisitesPath -Version $reqVersion

if ($DeployM365Prerequisites)
{
    Write-Log -Object ' '
    Write-Log -Object '-------------------------------------------------------------'
    Write-Log -Object ' Deploying all required modules from the PowerShell Gallery'
    Write-Log -Object '-------------------------------------------------------------'
    Write-Log -Object ' '
    $result = Install-DSCModulePrereqs -TargetPath $targetModulesPath -PrerequisitesPath $prerequisitesPath

    if ($result -eq $true)
    {
        Write-Log -Object 'Successfully retrieved all required modules from PowerShell Gallery'
    }
    else
    {
        Write-Log -Object '[ERROR] Unable to retrieve all required modules from PowerShell Gallery' -Failure
        Write-Host '##vso[task.complete result=Failed;]Failed'
    }
}

Write-Log -Object ' '
Write-Log -Object '----------------------------------------------------------------'
Write-Log -Object ' Correcting incorrect module folder names (bug in ModuleFast)'
Write-Log -Object '----------------------------------------------------------------'
Write-Log -Object ' '
$moduleFolders = Get-ChildItem -Path $targetModulesPath -Directory

foreach ($moduleFolder in $moduleFolders)
{
    $folders = Get-ChildItem -Path $moduleFolder.FullName -Directory
    foreach ($folder in $folders)
    {
        $manifestFilename = "{0}.psd1"-f $folder.Parent.Name
        $manifestFullPath = Join-Path -Path $folder.FullName -ChildPath $manifestFilename
        if (Test-Path -Path $manifestFullPath)
        {
            try
            {
                $manifestData = Import-PSDataFile -Path $manifestFullPath.ToString()

                if ($folder.Name -ne $manifestData.moduleVersion)
                {
                    Write-Log -Object "Folder: $($folder.Name) / Manifest: $($manifestData.moduleVersion) -> Incorrect. Correcting!"
                    Rename-Item -Path $folder.FullName -NewName $manifestData.moduleVersion
                }
            }
            catch
            {
            }
        }
    }
}

Write-Log -Object ' '
Write-Log -Object '----------------------------------------------------------------'
Write-Log -Object ' Listing all installed modules and their versions'
Write-Log -Object '----------------------------------------------------------------'
Write-Log -Object ' '
$moduleFolders = Get-ChildItem -Path $targetModulesPath -Directory

foreach ($moduleFolder in $moduleFolders)
{
    $versionFolders = Get-ChildItem -Path $moduleFolder.FullName -Directory
    foreach ($versionFolder in $versionFolders)
    {
        Write-Log -Object "- $($moduleFolder.Name) (v$($versionFolder.Name))"
    }
}

Write-Log -Object ' '
Write-Log -Object '*********************************************************'
Write-Log -Object '*  Finished Deployment of M365 DSC Module Dependencies  *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
