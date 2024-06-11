#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Checks if all referenced certificates exist in the Azure KeyVault.

.DESCRIPTION
    This script checks if all the referenced certificates actually exist in the Azure KeyVault.
    This to make sure the Deployment step is able to continue without any issues.

.PARAMETER KeyVault
    The name of the Azure KeyVault to use for retrieving secrets. This parameter is mandatory.

.EXAMPLE
    .\ValidateSecrets.ps1 -KeyVault "MyKeyVault"
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [System.String]
    $KeyVault
)

######## SCRIPT VARIABLES ########

$workingDirectoryCICD = $PSScriptRoot
$workingDirectoryData = Join-Path -Path $workingDirectoryCICD -ChildPath '..\..\Data' -Resolve
$dataFilesFolder = Join-Path -Path $workingDirectoryData -ChildPath '\DataFiles'

######## START SCRIPT ########
Set-Location -Path $workingDirectoryCICD
try
{
    Import-Module -Name '.\SupportFunctions.psm1' -ErrorAction Stop
}
catch
{
    Write-Host "ERROR: Could not load library 'SupportFunctions.psm1'. $($_.Exception.Message.Trim('.')). Exiting." -ForegroundColor Red
    exit -1
}

Write-Log -Object '*********************************************************'
Write-Log -Object '*     Starting Deployment of Microsoft365DSC Secrets    *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '

Write-Log -Object "Switching to path: $workingDirectoryCICD"
Set-Location -Path $workingDirectoryCICD

Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Reading environment-specific configuration file(s)'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '

[System.Array]$dataFiles = Get-ChildItem -Path (Join-Path -Path $dataFilesFolder -ChildPath 'Environments') -Filter '*#Generic.psd1' -Recurse

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Getting certificate secrets from Azure KeyVault'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '

$foundError = $false
foreach ($datafile in $dataFiles)
{
    Write-Log -Object "Processing data file: $($datafile.Name)"
    $envData = Import-PSDataFile $datafile.FullName
    $envShortName = $envData.NonNodeData.Environment.ShortName

    if ($envShortName -notmatch '^\w*$')
    {
        $envShortNameToken = $envShortName -replace "{" -replace "}"
        if ($envData.NonNodeData.Environment.Tokens.ContainsKey($envShortNameToken))
        {
            $envShortName = $envData.NonNodeData.Environment.Tokens.$envShortNameToken
        }
        else
        {
            Write-Log -Object "[ERROR] Invalid Environment ShortName value: $envShortNameToken" -Failure
            $foundError = $true
            continue
        }
    }
    Write-Log -Object ' '

    Write-Log -Object "Getting certificate secrets from KeyVault '$KeyVault'"
    foreach ($appcred in $envData.NonNodeData.AppCredentials)
    {
        $kvCertName = '{0}-Cert-{1}' -f $envShortName, $appCred.Workload
        Write-Log -Object "  Processing certificate: $kvCertName"

        $secret = Get-AzKeyVaultSecret -VaultName $KeyVault -Name $kvCertName -AsPlainText -ErrorAction SilentlyContinue
        if ($null -eq $secret)
        {
            Write-Log -Object "[ERROR] Cannot find $kvCertName in Azure KeyVault" -Failure
            $foundError = $true
        }
        else
        {
            Write-Log -Object "  Certificate $kvCertName found in Azure KeyVault"
        }
        Write-Log -Object ' '
    }
}

Write-Log -Object "Getting encryption certificate secret from KeyVault '$KeyVault'"

$encryptCertName = 'Cert-DSCEncrypt'
Write-Log -Object "Processing certificate: $encryptCertName"

$secret = Get-AzKeyVaultSecret -VaultName $KeyVault -Name $encryptCertName -AsPlainText -ErrorAction SilentlyContinue
if ($null -eq $secret)
{
    Write-Log -Object "[ERROR] Cannot find $encryptCertName in Azure KeyVault" -Failure
    $foundError = $true
}
else
{
    Write-Log -Object "Certificate $encryptCertName found in Azure KeyVault"
}

Write-Log -Object ' '
if ($foundError)
{
    Write-Log -Object 'RESULT: Validate Secrets script encountered errors!' -Failure
    Write-Host '##vso[task.complete result=Failed;]Failed'
}
else
{
    Write-Log -Object 'RESULT: Validate Secrets script completed successfully!'
}

Write-Log -Object ' '
Write-Log -Object '*********************************************************'
Write-Log -Object '*     Finished Deployment of Microsoft365DSC Secrets    *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
