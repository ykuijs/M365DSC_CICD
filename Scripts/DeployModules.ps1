#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Downloads and installs all required modules to the local machine.

.DESCRIPTION
    This script downloads and installs all required modules to the local machine, including the prepared Microsoft365DSC package from an
    Azure Blob Storage. This is required in the deployment pipeline.

.PARAMETER PackageSourceLocation
    The location of the NuGet repository to use for downloading the package. If not specified, the PowerShell Gallery will be used.

.PARAMETER PATToken
    The Personal Access Token (PAT) to use for authenticating with the NuGet repository. If not specified, no authentication will be used.

.PARAMETER DeployM365Prerequisites
    If specified, the script will also deploy the required Microsoft365DSC modules from an Azure Blob Storage.

.PARAMETER BlobResourceGroup
    The name of the resource group where the Azure Blob Storage is located. Required when DeployM365Prerequisites is specified.

.PARAMETER BlobStorageAccount
    The name of the Azure Blob Storage account. Required when DeployM365Prerequisites is specified.

.PARAMETER BlobContainer
    The name of the Azure Blob Storage container to use. Required when DeployM365Prerequisites is specified.

.EXAMPLE
    .\DeployModules.ps1

.EXAMPLE
    .\DeployModules.ps1 -DeployM365Prerequisites -BlobResourceGroup "MyResourceGroup" -BlobStorageAccount "MyStorageAccount" -BlobContainer "MyContainer"

.EXAMPLE
    .\DeployModules.ps1 -PackageSourceLocation https://dev.azure.com/MyProject/_packaging/MyFeed/nuget/v3/index.json -PATToken $PAT
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
[CmdletBinding()]
param
(
    [Parameter()]
    [AllowEmptyString()]
    [AllowNull()]
    [System.String]
    $PackageSourceLocation = $null,

    [Parameter()]
    [AllowEmptyString()]
    [AllowNull()]
    [System.String]
    $PATToken = $null,

    [Parameter()]
    [Switch]
    $DeployM365Prerequisites,

    [Parameter()]
    [System.String]
    $BlobResourceGroup,

    [Parameter()]
    [System.String]
    $BlobStorageAccount,

    [Parameter()]
    [System.String]
    $BlobContainer
)

######## SCRIPT VARIABLES ########

$workingDirectoryCICD = $PSScriptRoot
$rootDirectoryCICD = Split-Path -Path $workingDirectoryCICD

if ($DeployM365Prerequisites)
{
    # Deploy phase
    $workingDirectoryData = Join-Path -Path $rootDirectoryCICD -ChildPath '..\..\M365Automation\DeployPackage' -Resolve
    $prerequisitesPath = Join-Path -Path $workingDirectoryData -ChildPath 'DscResources.psd1' -Resolve
}
else
{
    # Build phase
    $prerequisitesPath = Join-Path -Path $rootDirectoryCICD -ChildPath 'DscResources.psd1' -Resolve
}

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
Write-Log -Object '*  Starting Deployment of M365 DSC Module Dependencies  *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
Write-Log -Object "Switching to path: $workingDirectoryCICD"
Set-Location -Path $workingDirectoryCICD

if ($DeployM365Prerequisites)
{
    if ($PSBoundParameters.ContainsKey('BlobResourceGroup') -eq $false -or `
            $PSBoundParameters.ContainsKey('BlobStorageAccount') -eq $false -or `
            $PSBoundParameters.ContainsKey('BlobContainer') -eq $false)
    {
        Write-Log '[ERROR] DeployM365Prerequisites was specified, but one or more required parameters BlobResourceGroup, BlobStorageAccount or BlobContainer are not specified!' -Failure
        Write-Log '[ERROR] Please add all of these parameters to continue!' -Failure
        Write-Host '##vso[task.complete result=Failed;]Failed'
        exit 10
    }

    Write-Log -Object ' '
    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' Checking required Microsoft365DSC version'
    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' '
    $reqModules = Import-PowerShellDataFile -Path $prerequisitesPath
    if ($reqModules.ContainsKey('Microsoft365DSC'))
    {
        $reqVersion = $reqModules.Microsoft365DSC
        Write-Log -Object "- Required version: $reqVersion"
    }
    else
    {
        Write-Log '[ERROR] Unable to find Microsoft365DSC in DscResources.psd1. Cancelling!' -Failure
        Write-Host '##vso[task.complete result=Failed;]Failed'
        exit 10
    }
}
else
{
    Write-Log -Object ' '
    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' Checking for presence of Microsoft365DSC module'
    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' '
    $reqVersion = Install-DSCModule -PrerequisitesPath $prerequisitesPath
}

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
Install-GenericModules -PrerequisitesPath $prerequisitesPath -PackageSourceLocation $PackageSourceLocation -PATToken $PATToken -Version $reqVersion

Write-Log -Object 'Importing module: M365DSCTools'
Import-Module -Name M365DSCTools -Force

if ($DeployM365Prerequisites)
{
    Write-Log -Object ' '
    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' Deploying all required modules from Azure Blob Storage'
    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' '
    $result = Get-ModulesFromBlobStorage -ResourceGroupName $BlobResourceGroup -StorageAccountName $BlobStorageAccount -ContainerName $BlobContainer -Version $reqVersion

    if ($result -eq $true)
    {
        Write-Log -Object 'Successfully retrieved all required modules from Azure Blob Storage'
    }
    else
    {
        Write-Log -Object '[ERROR] Unable to retrieve all required modules from Azure Blob Storage' -Failure
        Write-Host '##vso[task.complete result=Failed;]Failed'
    }
}

Write-Log -Object ' '
Write-Log -Object '*********************************************************'
Write-Log -Object '*  Finished Deployment of M365 DSC Module Dependencies  *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
