#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Downloads the Microsoft365DSC module and its dependencies, packages them into a Zip file and uploads that to an Azure Blob Storage.

.DESCRIPTION
    This script makes sure a Zip package of Microsoft365DSC and its dependencies is available in an Azure Blob Storage.
    It will download the modules from the PowerShell Gallery or a custom NuGet repository, package them into a Zip file
    and upload that to an Azure Blob Storage.

.PARAMETER PackageSourceLocation
    The location of the NuGet repository to use for downloading the modules. If not specified, the PowerShell Gallery will be used.

.PARAMETER PATToken
    The Personal Access Token (PAT) to use for authenticating with the NuGet repository. If not specified, no authentication will be used.

.PARAMETER BlobResourceGroup
    The name of the resource group where the Azure Blob Storage is located.

.PARAMETER BlobStorageAccount
    The name of the Azure Blob Storage account.

.PARAMETER BlobContainer
    The name of the Azure Blob Storage container to use.

.EXAMPLE
    .\CacheModules.ps1 -BlobResourceGroup "MyResourceGroup" -BlobStorageAccount "MyStorageAccount" -BlobContainer "MyContainer"

.EXAMPLE
    .\CacheModules.ps1 -PackageSourceLocation https://dev.azure.com/MyProject/_packaging/MyFeed/nuget/v3/index.json -PATToken $PAT -BlobResourceGroup "MyResourceGroup" -BlobStorageAccount "MyStorageAccount" -BlobContainer "MyContainer"
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

    [Parameter(Mandatory = $true)]
    [System.String]
    $BlobResourceGroup,

    [Parameter(Mandatory = $true)]
    [System.String]
    $BlobStorageAccount,

    [Parameter(Mandatory = $true)]
    [System.String]
    $BlobContainer
)

######## FUNCTIONS ########

Set-Location -Path $PSScriptRoot
try
{
    Import-Module -Name '.\SupportFunctions.psm1' -ErrorAction Stop
}
catch
{
    Write-Host "ERROR: Could not load library 'SupportFunctions.psm1'. $($_.Exception.Message.Trim('.')). Exiting." -ForegroundColor Red
    exit -1
}

######## SCRIPT VARIABLES ########

$workingDirectoryCICD = $PSScriptRoot
$rootDirectoryCICD = Split-Path -Path $workingDirectoryCICD
$prerequisitesPath = Join-Path -Path $rootDirectoryCICD -ChildPath 'DscResources.psd1' -Resolve

######## START SCRIPT ########

Write-Log -Object '***********************************************************'
Write-Log -Object '* Starting Caching of Microsoft365DSC Module Dependencies *'
Write-Log -Object '***********************************************************'
Write-Log -Object ' '

Write-Log -Object "Switching to path: $workingDirectoryCICD"
Set-Location -Path $workingDirectoryCICD

Write-Log -Object ' '
Write-Log -Object '-----------------------------------------------------------'
Write-Log -Object ' Checking for presence of Microsoft365DSC module'
Write-Log -Object '-----------------------------------------------------------'
Write-Log -Object ' '
$reqVersion = Get-RequiredM365DSCVersion -PrerequisitesPath $prerequisitesPath

#$packageExists = Test-IfModulesInBlobStorage -ResourceGroupName $BlobResourceGroup -StorageAccountName $BlobStorageAccount -ContainerName $BlobContainer -Version $reqVersion
$packageExists = $false
if ($packageExists -eq $false)
{
    Write-Log -Object ' '
    Write-Log -Object '-----------------------------------------------------------'
    Write-Log -Object ' Checking for presence of Microsoft365DSC module'
    Write-Log -Object '-----------------------------------------------------------'
    Write-Log -Object ' '
    $reqVersion = Install-DSCModule -PrerequisitesPath $prerequisitesPath

    Write-Log -Object ' '
    Write-Log -Object '-----------------------------------------------------------------------'
    Write-Log -Object ' Installing generic modules from PSGallery or a custom NuGet repository'
    Write-Log -Object '-----------------------------------------------------------------------'
    Write-Log -Object ' '
    Install-GenericModules -PrerequisitesPath $prerequisitesPath -PackageSourceLocation $PackageSourceLocation -PATToken $PATToken -Version $reqVersion

    Write-Log -Object 'Importing module: M365DSCTools'
    Import-Module -Name M365DSCTools -Force

    Write-Log -Object ' '
    Write-Log -Object '--------------------------------------------------------------------'
    Write-Log -Object ' Downloading and caching all required modules to Azure Blob Storage'
    Write-Log -Object '--------------------------------------------------------------------'
    Write-Log -Object ' '
    $result = Add-ModulesToBlobStorage -ResourceGroupName $BlobResourceGroup -StorageAccountName $BlobStorageAccount -ContainerName $BlobContainer

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
else
{
    Write-Log -Object 'Package for specified version already exists in the Azure Blob Storage'
}
Write-Log -Object ' '
Write-Log -Object '***********************************************************'
Write-Log -Object '* Finished Caching of Microsoft365DSC Module Dependencies *'
Write-Log -Object '***********************************************************'
Write-Log -Object ' '
