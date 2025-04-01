function New-M365DSCServicePrincipal
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [PSCredential]
        $Credential,

        [Parameter()]
        [System.String]
        $ServicePrincipalName = 'Microsoft365DSC_Deployment',

        [Parameter(Mandatory = $true)]
        [System.String]
        $CertificatePath,

        [Parameter()]
        [ValidateSet('Azure', 'AzureAD', 'AzureDevOps', 'Commerce', 'Defender', 'Exchange', 'Fabric', 'Intune', 'Office365', 'OneDrive', 'Planner', 'PowerPlatform', 'SecurityCompliance', 'Sentinel', 'ServicesHub', 'SharePoint', 'Teams')]
        [System.String]
        $Workload
    )

    begin
    {
        function Write-LogEntry
        {
            param
            (
                [Parameter(Mandatory = $true)]
                [System.String]
                $Object,

                [Parameter()]
                [Switch]
                $Failure
            )

            $timestamp = Get-Date -f 'yyyy-MM-dd HH:mm:ss'
            $type = "INFO"
            if ($Failure)
            {
                $type = "ERROR"
            }
            $message = "[{0}] [{1}] {2}" -f $timestamp, $type, $object

            Write-Host -Object "[$timestamp] [" -NoNewline
            if ($Failure)
            {
                Write-Host -Object "$type" -ForegroundColor Red -NoNewline
            }
            else
            {
                Write-Host -Object "$type" -ForegroundColor Green -NoNewline
            }
            Write-Host -Object "] $object"
        }

        $currProgressPreference = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'

        $workingDirectory = $PSScriptRoot

        Write-LogEntry -Object "Starting Service Principal Creation script"
        Set-Location -Path $workingDirectory
    }

    process
    {
        if ((Test-Path -Path $CertificatePath) -eq $false)
        {
            Write-LogEntry -Object "Cannot find file '$CertificatePath' specified in the parameter CertificatePath. Please make sure the file exists!" -Failure
            return
        }

        try
        {
            $certObj = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certObj.Import($CertificatePath)
        }
        catch
        {
            Write-LogEntry -Object "Error reading '$CertificatePath'. Please make sure the file is a valid CER file!" -Failure
            return
        }

        Connect-MgGraph -Scopes 'Application.ReadWrite.All','Organization.Read.All','Directory.Read.All','RoleManagement.ReadWrite.Directory' -NoWelcome

        Write-LogEntry -Object "Checking for presence of AAD / Entra ID Premium P2 license"
        $aadPremiumP2Found = $false
        $skus = Get-MgBetaSubscribedSku
        foreach ($sku in $skus)
        {
            if ($sku.ServicePlans.ServicePlanName -contains "AAD_PREMIUM_P2")
            {
                $aadPremiumP2Found = $true
                break
            }
        }

        $tenantid = (Get-MgContext).TenantId

        Write-LogEntry -Object 'Retrieving required permissions'
        $allResourcePaths = Get-ChildItem -Path (Join-Path -Path (Split-Path -Path (Get-Module -Name Microsoft365DSC).Path) -ChildPath 'DSCResources') -Recurse -Filter '*.psm1'
        $allResources = $allResourcePaths.Name -replace '^MSFT_', '' -replace '.psm1$', ''
        if ([String]::IsNullOrEmpty($Workload))
        {
            Write-LogEntry -Object '  No Workload specified, retrieving all resources'
            $resources = Get-M365DSCAllResources
        }
        else
        {
            Write-LogEntry -Object "  Workload '$Workload' specified, retrieving all resources for this workload"
            switch ($Workload)
            {
                'Azure' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'Azure*'}
                }
                'AzureAD' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'AAD*'}
                }
                'AzureDevOps' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'ADO*'}
                }
                'Commerce' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'Commerce*'}
                }
                'Defender' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'Defender*'}
                }
                'Exchange' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'EXO*'}
                }
                'Fabric' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'Fabric*'}
                }
                'Intune' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'Intune*'}
                }
                'Office365' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'O365*'}
                }
                'OneDrive' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'OD*'}
                }
                'Planner' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'Planner*'}
                }
                'PowerPlatform' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'PP*'}
                }
                'SecurityCompliance' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'SC*'}
                }
                'Sentinel' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'Sentinel*'}
                }
                'ServicesHub' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'SH*'}
                }
                'SharePoint' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'SPO*'}
                }
                'Teams' {
                    $resources = $allResources | Where-Object -FilterScript { $_ -like 'Teams*'}
                }
            }
        }
        [Array]$permissions = Get-M365DSCCompiledPermissionList -ResourceNameList $resources -PermissionType 'Application' -AccessType 'Update'

        if ([String]::IsNullOrWhiteSpace($Workload) -or $Workload -eq 'SharePoint')
        {
            Write-LogEntry -Object 'Checking additionally required SharePoint permissions'
            $spPerms = @("Sites.FullControl.All","AllSites.FullControl","User.ReadWrite.All")
            foreach ($spPerm in $spPerms)
            {
                if ($null -eq ($permissions | Where-Object { $_.API -eq 'SharePoint' -and $_.PermissionName -eq $spPerm}))
                {
                    $permissions += @{
                        API = 'SharePoint'
                        PermissionName = $spPerm
                    }
                }
            }
        }

        Write-LogEntry -Object 'Checking additionally required Graph permissions'
        $graphPerms = @("Group.ReadWrite.All","User.ReadWrite.All")
        foreach ($graphPerm in $graphPerms)
        {
            if ($null -eq ($permissions | Where-Object { $_.API -eq 'SharePoint' -and $_.PermissionName -eq $graphPerm}))
            {
                $permissions += @{
                    API = 'Graph'
                    PermissionName = $graphPerm
                }
            }
        }

        Write-LogEntry -Object "All required permissions: $($permissions.PermissionName -join " / " )" -Verbose

        $azureADApp = Get-MgApplication -Filter "DisplayName eq '$($ServicePrincipalName)'"

        $params = @{
            ApplicationName = $ServicePrincipalName
            Permissions     = $permissions
            AdminConsent    = $true
            Credential      = $Credential
            Type            = 'Certificate'
            CertificatePath = $CertificatePath
        }

        if ($null -eq $azureADApp)
        {
            Write-LogEntry -Object "Service Principal '$ServicePrincipalName' does NOT exist. Creating service principal."
        }
        else
        {
            Write-LogEntry -Object "Service Principal '$ServicePrincipalName' exists. Updating service principal."
        }

        Update-M365DSCAzureAdApplication @params

        # Refresh app details
        $found = $false
        Write-LogEntry -Object "Retrieving app details"
        do
        {
            $app = Get-MgServicePrincipal -Filter "DisplayName eq '$($ServicePrincipalName)'"

            if ($null -eq $app)
            {
                Write-LogEntry -Object "App not yet found, waiting for 5 seconds"
                Start-Sleep -Seconds 5
            }
            else
            {
                $found = $true
            }
        } until ($found -eq $true)

        if ([String]::IsNullOrWhiteSpace($Workload) -or $Workload -eq 'SharePoint')
        {
            Write-LogEntry -Object "Updating 'Allow Public Client Flows' setting (IsFallbackPublicClient), required for SharePoint"
            $azureADApp = Get-MgApplication -Filter "DisplayName eq '$($ServicePrincipalName)'"
            Update-MgApplication -ApplicationId $azureADApp.Id -IsFallbackPublicClient
        }

        $applicationId = $app.AppId

        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($CertificatePath)

        $certThumbprint = $cert.Thumbprint

        $domain = (Get-MgBetaOrganization).VerifiedDomains | Where-Object { $_.IsInitial -eq $true }
        $domainName = $domain.Name

        Write-LogEntry -Object ' '
        Write-LogEntry -Object 'Details of Service Principal:'
        Write-LogEntry -Object "ApplicationId        : $applicationId"
        Write-LogEntry -Object "TenantId             : $tenantid"
        Write-LogEntry -Object "TenantName           : $domainName"
        Write-LogEntry -Object "CertificateThumbprint: $certThumbprint"
        Write-LogEntry -Object "ApplicationId        : $applicationId"
        Write-LogEntry -Object 'NOTE: Make sure you copy these details for the next steps!'
        Write-LogEntry -Object ' '

        if ($aadPremiumP2Found -eq $true)
        {
            Write-LogEntry -Object "AAD Premium P2 detected, using PIM to assign service principal to role"
        }
        else
        {
            Write-LogEntry -Object "AAD Premium P2 NOT detected, using direct assignments of service principal to role"
        }

        $roles = @('Exchange Administrator','Compliance Administrator')

        foreach ($role in $roles)
        {
            if (($role -eq 'Exchange Administrator' -and $Workload -eq 'Exchange') -or ($role -eq 'Compliance Administrator' -and $Workload -eq 'SecurityCompliance'))
            {
                $roleId = Get-MgBetaDirectoryRoleTemplate | Where-Object {$_.displayName -eq $role} | Select-Object -ExpandProperty Id

                $roleDefinition = Get-MgBetaRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $roleId
                $roleAssignments = Get-MgBetaRoleManagementDirectoryRoleAssignment -Filter "roleDefinitionId eq '$($roleDefinition.Id)' and principalId eq '$($app.Id)'"
                if ($null -ne $roleAssignments)
                {
                    Write-LogEntry -Object "Service principal is already assigned to role $role."
                }
                else
                {
                    Write-LogEntry -Object "Service principal is NOT assigned to role $role. Adding to role."
                    $null = New-MgBetaRoleManagementDirectoryRoleAssignment -PrincipalId $app.Id -RoleDefinitionId $roleDefinition.Id -DirectoryScopeId "/"
                }
            }
        }
    }

    end
    {
        $ProgressPreference = $currProgressPreference

        Write-LogEntry -Object "Completed Service Principal Creation script"
    }
}
