Configuration M365Configuration
{
    Import-DscResource -ModuleName M365DSC.CompositeResources

    node localhost
    {
        $azureAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Azure' }
        $azureadAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'AzureAD' }
        $azuredoAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'AzureDevOps' }
        $defenderAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Defender' }
        $exchangeAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Exchange' }
        $fabricAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Fabric' }
        $intuneAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Intune' }
        $officeAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Office365' }
        $onedriveAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'OneDrive' }
        $plannerAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Planner' }
        $powerplatformAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'PowerPlatform' }
        $securitycomplianceAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'SecurityCompliance' }
        $sentinelAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Sentinel' }
        $sharepointAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'SharePoint' }
        $teamsAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Teams' }

        # Azure Composite Resource
        if ($null -ne $azureAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Azure -eq $true)
        {
            Azure 'Azure_Configuration'
            {
                ApplicationId         = $azureAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $azureAppCreds.CertThumbprint
            }
        }

        # Azure AD / Entra ID Composite Resource
        if ($null -ne $azureadAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.AzureAD -eq $true)
        {
            AzureAD 'AzureAD_Configuration'
            {
                ApplicationId         = $azureadAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $azureadAppCreds.CertThumbprint
            }
        }

        # Azure DevOps Composite Resource
        if ($null -ne $azuredoAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.AzureDevOps -eq $true)
        {
            AzureDevOps 'AzureDevOps_Configuration'
            {
                ApplicationId         = $azuredoAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $azuredoAppCreds.CertThumbprint
            }
        }

        # Defender Composite Resource
        if ($null -ne $defenderAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Defender -eq $true)
        {
            Defender 'Defender_Configuration'
            {
                ApplicationId         = $defenderAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $defenderAppCreds.CertThumbprint
            }
        }

        # Exchange Composite Resource
        if ($null -ne $exchangeAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Exchange -eq $true)
        {
            Exchange 'Exchange_Configuration'
            {
                ApplicationId         = $exchangeAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $exchangeAppCreds.CertThumbprint
            }
        }

        # Fabric Composite Resource
        if ($null -ne $fabricAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Fabric -eq $true)
        {
            Fabric 'Fabric_Configuration'
            {
                ApplicationId         = $fabricAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $fabricAppCreds.CertThumbprint
            }
        }

        # Intune Composite Resource
        if ($null -ne $intuneAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Intune -eq $true)
        {
            Intune 'Intune_Configuration'
            {
                ApplicationId         = $intuneAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $intuneAppCreds.CertThumbprint
            }
        }

        # Office 365 Composite Resource
        if ($null -ne $officeAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Office365 -eq $true)
        {
            Office365 'Office365_Configuration'
            {
                ApplicationId         = $officeAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $officeAppCreds.CertThumbprint
            }
        }

        # OneDrive Composite Resource
        if ($null -ne $onedriveAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.OneDrive -eq $true)
        {
            OneDrive 'OneDrive_Configuration'
            {
                ApplicationId         = $onedriveAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $onedriveAppCreds.CertThumbprint
            }
        }

        # Planner Composite Resource
        if ($null -ne $plannerAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Planner -eq $true)
        {
            Planner 'Planner_Configuration'
            {
                ApplicationId         = $plannerAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $plannerAppCreds.CertThumbprint
            }
        }

        # PowerPlatform Composite Resource
        if ($null -ne $powerplatformAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.PowerPlatform -eq $true)
        {
            PowerPlatform 'PowerPlatform_Configuration'
            {
                ApplicationId         = $powerplatformAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $powerplatformAppCreds.CertThumbprint
            }
        }

        # Security Compliance Composite Resource
        if ($null -ne $securitycomplianceAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.SecurityCompliance -eq $true)
        {
            SecurityCompliance 'SecurityCompliance_Configuration'
            {
                ApplicationId         = $securitycomplianceAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $securitycomplianceAppCreds.CertThumbprint
            }
        }

        # Sentinel Composite Resource
        if ($null -ne $sentinelAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Sentinel -eq $true)
        {
            Sentinel 'Sentinel_Configuration'
            {
                ApplicationId         = $sentinelAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $sentinelAppCreds.CertThumbprint
            }
        }

        # SharePoint Composite Resource
        if ($null -ne $sharepointAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.SharePoint -eq $true)
        {
            SharePoint 'SharePoint_Configuration'
            {
                ApplicationId         = $sharepointAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $sharepointAppCreds.CertThumbprint
            }
        }

        # Teams Composite Resource
        if ($null -ne $teamsAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Teams -eq $true)
        {
            Teams 'Teams_Configuration'
            {
                ApplicationId         = $teamsAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $teamsAppCreds.CertThumbprint
            }
        }
    }
}
