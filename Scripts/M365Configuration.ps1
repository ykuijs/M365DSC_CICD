Configuration M365Configuration
{
    Import-DscResource -ModuleName M365DSC.CompositeResources

    node localhost
    {
        $azureadAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'AzureAD' }
        $exchangeAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Exchange' }
        $intuneAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Intune' }
        $officeAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Office365' }
        $onedriveAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'OneDrive' }
        $plannerAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Planner' }
        $powerplatformAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'PowerPlatform' }
        $securitycomplianceAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'SecurityCompliance' }
        $sharepointAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'SharePoint' }
        $teamsAppCreds = $ConfigurationData.NonNodeData.AppCredentials | Where-Object -FilterScript { $_.Workload -eq 'Teams' }

        if ($null -ne $azureadAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.AzureAD -eq $true)
        {
            AzureAD 'AzureAD_Configuration'
            {
                ApplicationId         = $azureadAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $azureadAppCreds.CertThumbprint
            }
        }

        if ($null -ne $exchangeAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Exchange -eq $true)
        {
            Exchange 'Exchange_Configuration'
            {
                ApplicationId         = $exchangeAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $exchangeAppCreds.CertThumbprint
            }
        }

        if ($null -ne $intuneAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Intune -eq $true)
        {
            Intune 'Intune_Configuration'
            {
                ApplicationId         = $intuneAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $intuneAppCreds.CertThumbprint
            }
        }

        if ($null -ne $officeAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Office365 -eq $true)
        {
            Office365 'Office365_Configuration'
            {
                ApplicationId         = $officeAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $officeAppCreds.CertThumbprint
            }
        }

        if ($null -ne $onedriveAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.OneDrive -eq $true)
        {
            OneDrive 'OneDrive_Configuration'
            {
                ApplicationId         = $onedriveAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $onedriveAppCreds.CertThumbprint
            }
        }

        if ($null -ne $plannerAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.Planner -eq $true)
        {
            Planner 'Planner_Configuration'
            {
                ApplicationId         = $plannerAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $plannerAppCreds.CertThumbprint
            }
        }

        if ($null -ne $powerplatformAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.PowerPlatform -eq $true)
        {
            PowerPlatform 'PowerPlatform_Configuration'
            {
                ApplicationId         = $powerplatformAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $powerplatformAppCreds.CertThumbprint
            }
        }

        if ($null -ne $securitycomplianceAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.SecurityCompliance -eq $true)
        {
            SecurityCompliance 'SecurityCompliance_Configuration'
            {
                ApplicationId         = $securitycomplianceAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $securitycomplianceAppCreds.CertThumbprint
            }
        }

        if ($null -ne $sharepointAppCreds -and $ConfigurationData.NonNodeData.Environment.UsedWorkloads.SharePoint -eq $true)
        {
            SharePoint 'SharePoint_Configuration'
            {
                ApplicationId         = $sharepointAppCreds.ApplicationId
                TenantId              = $ConfigurationData.NonNodeData.Environment.TenantId
                CertificateThumbprint = $sharepointAppCreds.CertThumbprint
            }
        }

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
