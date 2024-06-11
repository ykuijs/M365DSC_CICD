#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Retrieves the certificates from the Azure KeyVault and installs them on the local machine.

.DESCRIPTION
    This script retrieves the authentication certificates from the Azure KeyVault and installs
    them on the local machine. It also configures the Local Configuration Manager (LCM) with the
    encryption certificate.

.PARAMETER KeyVault
    The name of the Azure KeyVault to use for retrieving secrets. This parameter is mandatory.

.PARAMETER Environment
    The environment to be deployed. If not specified, all environments will be processed.

.EXAMPLE
    .\DownloadSecrets.ps1 -KeyVault "MyKeyVault" -Environment "Dev"
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [System.String]
    $KeyVault,

    [Parameter()]
    [System.String]
    $Environment
)

######## SCRIPT VARIABLES ########

$workingDirectoryCICD = $PSScriptRoot
$workingDirectoryData = Join-Path -Path $workingDirectoryCICD -ChildPath '..\..\..\M365Automation\DeployPackage' -Resolve

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

if ($Environment)
{
    Write-Log -Object "Getting data file for environment '$Environment'"
    $envPath = Get-ChildItem -Path $workingDirectoryData -Directory -Filter $Environment -Recurse
    $dataFilePath = Join-Path -Path $envPath.FullName -ChildPath "$Environment.psd1"
    [array]$dataFiles = Get-Item -Path $dataFilePath
}
else
{
    [array]$dataFiles = Get-ChildItem -Path $workingDirectoryData -Filter '*.psd1' -Recurse -Exclude '*Original*','DscResources.psd1'
    Write-Log -Object "- Found $($dataFiles.Count) data file(s)"
}

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Getting certificate secrets from Azure KeyVault'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '

foreach ($datafile in $dataFiles)
{
    Write-Log -Object "Processing data file: $($datafile.Name)"
    $envData = Import-PSDataFile $datafile.FullName
    $envShortName = $envData.NonNodeData.Environment.ShortName

    if ($envShortName -notmatch '^\w*$')
    {
        Write-Log -Object "[ERROR] Invalid Environment ShortName value: $envShortName" -Failure
        Write-Host '##vso[task.complete result=Failed;]Failed'
        exit -1
    }

    Write-Log -Object "Getting certificate secrets from KeyVault '$KeyVault'"
    $certsImported = @()
    foreach ($appcred in $envData.NonNodeData.AppCredentials)
    {
        $kvCertName = '{0}-Cert-{1}' -f $envShortName, $appCred.Workload
        Write-Log -Object "Processing certificate: $kvCertName"

        $secret = Get-AzKeyVaultSecret -VaultName $KeyVault -Name $kvCertName -AsPlainText -ErrorAction SilentlyContinue
        if ($null -eq $secret)
        {
            Write-Log -Object "[ERROR] Cannot find $kvCertName in Azure KeyVault" -Failure
            Write-Error 'Build failed!'
            Write-Host '##vso[task.complete result=Failed;]Failed'
            exit 20
        }
        $secretByte = [Convert]::FromBase64String($secret)

        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($secretByte, '', 'Exportable,MachineKeySet,PersistKeySet')
        Write-Log -Object "Importing certificate $kvCertName with thumbprint $($cert.Thumbprint) into the LocalMachine Certificate Store"
        if ((Test-Path -Path "Cert:\LocalMachine\My\$($cert.Thumbprint)") -eq $false)
        {
            $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
            $CertStore.Open('ReadWrite')
            $CertStore.Add($cert)
            $CertStore.Close()
        }
        else
        {
            Write-Log -Object 'Certificate already exists. Skipping...'
        }

        Write-Log -Object "Importing certificate $kvCertName with thumbprint $($cert.Thumbprint) into the 'NT AUTHORITY\System' User Certificate Store"
        if ($certsImported -notcontains $cert.Thumbprint)
        {
            $sysScript = "
				`$secretByte = [Convert]::FromBase64String('$secret')
				`$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(`$secretByte, '', 'Exportable,UserKeySet,PersistKeySet')
				if ((Test-Path -Path ('Cert:\CurrentUser\My\' + `$cert.Thumbprint)) -eq `$false) {
					`$CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','CurrentUser')
					`$CertStore.Open('ReadWrite')
					`$CertStore.Add(`$cert)
					`$CertStore.Close()
					`$cert.Reset()
				}
			"
            $tempPref = $ErrorActionPreference
            $ErrorActionPreference = 'SilentlyContinue'
            .\PsExec.exe -accepteula -nobanner -s powershell.exe -command "Invoke-Command -ScriptBlock {$sysScript}" *> $null
            $certsImported += $cert.Thumbprint
            $ErrorActionPreference = $tempPref
        }
        else
        {
            Write-Log -Object 'Certificate already exists. Skipping...'
        }
        $cert.Reset()
    }
}

Write-Log -Object "Getting encryption certificate secret from KeyVault '$KeyVault'"

$encryptCertName = 'Cert-DSCEncrypt'
Write-Log -Object "Processing certificate: $encryptCertName"

$secret = Get-AzKeyVaultSecret -VaultName $KeyVault -Name $encryptCertName -AsPlainText -ErrorAction SilentlyContinue
if ($null -eq $secret)
{
    Write-Log -Object "[ERROR] Cannot find $encryptCertName in Azure KeyVault" -Failure
    Write-Error 'Build failed!'
    Write-Host '##vso[task.complete result=Failed;]Failed'
    exit 20
}
$secretByte = [Convert]::FromBase64String($secret)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($secretByte, '', 'Exportable,MachineKeySet,PersistKeySet')
Write-Log -Object "Importing certificate $encryptCertName with thumbprint $($cert.Thumbprint) into the LocalMachine Certificate Store"
if ((Test-Path -Path "Cert:\LocalMachine\My\$($cert.Thumbprint)") -eq $false)
{
    $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
    $CertStore.Open('ReadWrite')
    $CertStore.Add($cert)
    $CertStore.Close()
}
else
{
    Write-Log -Object 'Certificate already exists. Skipping...'
}

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Configuring LCM with the encryption certificate'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '

Configuration ConfigureLCM {
    Import-DscResource -ModuleName PsDesiredStateConfiguration
    node localhost {
        LocalConfigurationManager
        {
            ConfigurationMode = 'ApplyOnly'
            CertificateId     = $cert.Thumbprint
        }
    }
}
$LCMConfig = ConfigureLCM
Set-DscLocalConfigurationManager -Path $LCMConfig.Directory
Get-DscLocalConfigurationManager | Format-Table -Property CertificateID, ConfigurationMode -AutoSize
$cert.Reset()

Write-Log -Object ' '
Write-Log -Object '*********************************************************'
Write-Log -Object '*     Finished Deployment of Microsoft365DSC Secrets    *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
