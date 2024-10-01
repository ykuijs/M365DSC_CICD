#Requires -Version 5.1
#Requires -Modules Az.KeyVault
#Requires -RunAsAdministrator

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [System.String]
    $VaultName,

    [Parameter(Mandatory = $true)]
    [System.String]
    $DataFileFolder
)

begin
{
    ######## FUNCTIONS ########
    function Write-Log
    {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [System.String]
            $Message,

            [Parameter()]
            [System.Int32]
            $Level = 0,

            [Parameter()]
            [ValidateSet('Information', 'Warning', 'Error')]
            [System.String]
            $Type = 'Information',

            [Parameter()]
            [Switch]
            $NoNewLine
        )

        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $indentation = '  ' * $Level
        $params = @{}

        switch ($Type)
        {
            "Information" {
                $params.ForeGroundColor = 'Cyan'
                $infoType = 'INFO'
            }
            "Warning" {
                $params.ForeGroundColor = 'Yellow'
                $infoType = 'WARNING'
            }
            "Error" {
                $params.ForeGroundColor = 'Red'
                $infoType = 'ERROR'
            }
        }

        $params.Object = '{0} [{1}] {2}{3}' -f $timestamp, $infoType, $indentation, $Message

        if ($NoNewLine)
        {
            $params.NoNewline = $true
        }

        Write-Host @params
    }

    function Connect-Azure
    {
        $WarningPreference = 'SilentlyContinue'
        $null = Connect-AzAccount

        Write-Log -Message 'Checking available tenants' -Level 1
        $tenants = Get-AzTenant
        if ($tenants.Count -gt 1)
        {
            Write-Log -Message 'Found multiple tenants, specify which tenant you would like to use:' -Level 1
            $i = 0
            foreach ($tenant in $tenants)
            {
                $i++
                Write-Log -Message ('{0:D2} - {1} ({2})' -f $i, $tenant.Name, $tenant.Id) -Level 2
            }
            $validInput = $false
            do
            {
                $inputTenantNo = Read-Host -Prompt 'Enter number of tenant'
                $tenantnr = 0
                if ([int]::TryParse($inputTenantNo, [ref]$tenantnr))
                {
                    if ($tenantnr -le 0 -or $tenantnr -gt $i)
                    {
                        Write-Log -Message 'Provided number is not valid. Please try again!'
                    }
                    else
                    {
                        $validInput = $true

                        #Correcting for zero based array
                        $tenantnr--
                    }
                }
                else
                {
                    Write-Log -Message 'Provided input is not a number. Please try again!'
                }
            }
            until ($validInput)

            Write-Log -Message "Switching tenant to $($tenants[$tenantnr].Name)"
            $null = Set-AzContext -Tenant $tenants[$tenantnr]
        }

        $WarningPreference = 'Continue'
    }

    Write-Log -Message 'Starting script!'
    Write-Log -Message ' '

    if ($null -ne $psISE)
    {
        Write-Log -Message "Use of the PowerShell ISE is not supported. Please use a PowerShell window!" -Type 'Error'
        exit
    }
}

process
{
    ######## START SCRIPT ########
    if ((Test-Path -Path $DataFileFolder) -eq $false)
    {
        Write-Log -Message "Cannot find the specified folder '$DataFileFolder'. Please make sure you specify a path that exists!" -Type 'Error'
        return
    }

    $connection = Get-AzContext
    if ($null -eq $connection)
    {
        Write-Log -Message 'Connecting to Azure'
        Connect-Azure
    }
    else
    {
        Write-Log -Message 'Already connected to Azure'
        Write-Log -Message "Environment  : $($connection.Environment)" -Level 1
        Write-Log -Message "Subscription : $(($connection.Name -split ' ')[0])" -Level 1
        Write-Log -Message "Account      : $($connection.Account)" -Level 1

        $result = Read-Host -Prompt 'Do you want to use these credentials (y/N)?'
        if ($result.ToLower() -eq 'y')
        {
            Write-Log -Message 'Continuing with these credentials!'
        }
        else
        {
            Write-Log -Message 'Reconnecting to Microsoft Azure!'
            $null = Disconnect-AzAccount
            Connect-Azure
        }
    }

    $KeyVault = Get-AzKeyVault -VaultName $VaultName
    if ($null -eq $KeyVault)
    {
        Write-Log -Message "Cannot find the specified Key Vault '$VaultName'. Please make sure you specify a valid vault!" -Type 'Error'
        return
    }

    #### UPDATE CODE
    $envName = Split-Path -Path $DataFileFolder -Leaf
    Write-Log -Message "Processing environment $envName"
    $dataFilePath = Join-Path -Path $DataFileFolder -ChildPath "$envName#Generic.psd1"

    if ((Test-Path -Path $dataFilePath) -eq $false)
    {
        Write-Log -Message "Specified DataFile does not exist: $dataFilePath" -Type 'Error'
        return
    }

    Write-Log -Message "Processing file '$dataFilePath'"
    $data = Import-PowerShellDataFile $dataFilePath
    $envShortName = $data.NonNodeData.Environment.ShortName

    if ($envShortName -match "^{{(.*)}}$")
    {
        $token = $Matches[1]
        Write-Log -Message "Token is used. Checking value of token '$token'"
        if ($null -eq $data.NonNodeData.Environment.Tokens.$token)
        {
            Write-Log -Message "Specified token was not found. Please check!" -Type 'Error'
            return
        }
        $envShortName = $data.NonNodeData.Environment.Tokens.$token
    }

    Write-Log -Message ' '
    Write-Log -Message 'Processing AppCredential certificates'
    $certificatesUpdated = 0
    $certificatePasswordsUpdated = 0
    foreach ($appCred in $data.NonNodeData.AppCredentials)
    {
        $updateCertificate = $false

        $kvSecretName = '{0}-CertPw-{1}' -f $envShortName, $appCred.Workload
        Write-Log -Message "Checking certificate password $kvSecretName" -Level 1

        $kvSecret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $kvSecretName
        if ($null -eq $kvSecret)
        {
            Write-Log -Message 'Certificate password does not exist, adding it to Key Vault' -Level 2
            $updateCertificate = $true
        }
        else
        {
            Write-Log 'Certificate password already exists. Do you want to overwrite it (y/N)? ' -Level 2 -NoNewLine
            $securePassword = $kvSecret.SecretValue
            $answer = Read-Host
            if ($answer.ToLower() -eq 'y')
            {
                $updateCertificate = $true
            }
        }

        if ($updateCertificate -eq $true)
        {
            $params = @{
                Message = "Enter password for $envShortName $($appCred.Workload): "
                Level   = 2
            }
            Write-Log @params

            $securePassword = Read-Host -AsSecureString
            Write-Log "Updating secret $kvSecretName" -Level 2
            $null = Set-AzKeyVaultSecret -VaultName $VaultName -Name $kvSecretName -SecretValue $securePassword
            $certificatePasswordsUpdated++
        }
        else
        {
            Write-Log "Skipping secret $kvSecretName" -Level 2
        }

        $kvCertName = '{0}-Cert-{1}' -f $envShortName, $appCred.Workload
        Write-Log -Message "Checking certificate $kvCertName" -Level 1

        $updateCertificate = $false
        $kvCertificate = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $kvCertName
        if ($null -eq $kvCertificate)
        {
            Write-Log -Message 'Certificate does not exist, adding it to Key Vault' -Level 2
            $updateCertificate = $true
        }
        else
        {
            if ($kvCertificate.Thumbprint -ne $appCred.CertThumbprint)
            {
                Write-Log 'Certificate has a different thumbprint. Updating certificate!' -Level 2
                $updateCertificate = $true
            }
            else
            {
                Write-Log 'Certificate already exists. Skipping certificate!' -Level 2
            }
        }

        if ($updateCertificate -eq $true)
        {
            # Dialog for selecting PFX input file
            Add-Type -AssemblyName System.Windows.Forms
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.InitialDirectory = $PSScriptRoot
            $dialog.Title = "Please select the $envShortName $($appCred.Workload) certificate Pfx file"
            $dialog.Filter = 'Pfx (*.pfx) | *.pfx'
            $result = $dialog.ShowDialog()

            if ($result -eq 'OK')
            {
                $importedCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $kvCertName -Password $securePassword -FilePath $dialog.FileName
                if ($importedCert.Thumbprint -ne $appCred.CertThumbprint)
                {
                    Write-Warning "Selected certificate does not match the Thumbprint specified in the data file (Certificate: $($importedCert.Thumbprint) / Data file: $($appCred.CertThumbprint)"
                }
                $certificatesUpdated++
            }
        }
        else
        {
            Write-Log "Skipping secret $envShortName" -Level 2
        }
    }

    Write-Log -Message ' '
    Write-Log -Message 'Processing encryption certificate'
    $updateCertificate = $false

    $kvSecretName = 'CertPw-DSCEncrypt'
    Write-Log -Message "Checking certificate password $kvSecretName" -Level 1

    $kvSecret = Get-AzKeyVaultSecret -VaultName $VaultName -Name $kvSecretName
    if ($null -eq $kvSecret)
    {
        Write-Log -Message 'Certificate password does not exist, adding it to Key Vault' -Level 2
        $updateCertificate = $true
    }
    else
    {
        Write-Log 'Certificate password already exists. Do you want to overwrite it (y/N)? ' -Level 2 -NoNewLine
        $securePassword = $kvSecret.SecretValue
        $answer = Read-Host
        if ($answer.ToLower() -eq 'y')
        {
            $updateCertificate = $true
        }
    }

    if ($updateCertificate -eq $true)
    {
        $params = @{
            Message = 'Enter password for encryption certificate: '
            Level   = 2
        }
        Write-Log @params

        $securePassword = Read-Host -AsSecureString
        Write-Log "Updating secret $kvSecretName" -Level 2
        $null = Set-AzKeyVaultSecret -VaultName $VaultName -Name $kvSecretName -SecretValue $securePassword
        $certificatePasswordsUpdated++
    }
    else
    {
        Write-Log "Skipping secret $kvSecretName" -Level 2
    }

    $kvCertName = 'Cert-DSCEncrypt'
    Write-Log -Message "Checking certificate $kvCertName" -Level 1

    $updateCertificate = $false
    $kvCertificate = Get-AzKeyVaultCertificate -VaultName $VaultName -Name $kvCertName
    if ($null -eq $kvCertificate)
    {
        Write-Log -Message 'Certificate does not exist, adding it to Key Vault' -Level 2
        $updateCertificate = $true
    }
    else
    {
        Write-Log 'Updating certificate!' -Level 2
        $updateCertificate = $true
    }

    if ($updateCertificate -eq $true)
    {
        # Dialog for selecting PFX input file
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.OpenFileDialog
        $dialog.InitialDirectory = $PSScriptRoot
        $dialog.Title = 'Please select the encryption certificate Pfx file'
        $dialog.Filter = 'Pfx (*.pfx) | *.pfx'
        $result = $dialog.ShowDialog()

        if ($result -eq 'OK')
        {
            $importedCert = Import-AzKeyVaultCertificate -VaultName $VaultName -Name $kvCertName -Password $securePassword -FilePath $dialog.FileName
            $certificatesUpdated++
        }
    }
    else
    {
        Write-Log "Skipping certificate $kvCertName" -Level 2
    }

    Write-Log -Message "Updated $certificatePasswordsUpdated certificate passwords!"
    Write-Log -Message "Updated $certificatesUpdated certificates!"
}

end
{
    Write-Log -Message ' '
    Write-Log -Message 'Completed script!'
}
