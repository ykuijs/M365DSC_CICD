#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Checks the compliance of all Microsoft 365 tenants with the DSC configurations.

.DESCRIPTION
    This script uses the created MOF files to check if the corresponding tenants are
    in compliance with these DSC configurations.

.PARAMETER UseMail
    If set to $true, the script will send the compliance report via email.

.PARAMETER MailTenantId
    The Tenant ID of the Azure AD tenant to use for sending the email.

.PARAMETER MailAppId
    The Application ID of the Azure AD application to use for sending the email.

.PARAMETER MailAppSecret
    The Secret of the Azure AD application to use for sending the email.

.PARAMETER MailFrom
    The email address to use as the sender of the email.

.PARAMETER MailTo
    The email address to use as the recipient of the email.

.PARAMETER UseTeams
    If set to $true, the script will send the compliance report via Microsoft Teams.

.PARAMETER TeamsWebhook
    The Webhook URL to use for sending the message to Microsoft Teams.

.EXAMPLE
    .\CheckDscCompliance.ps1 -UseMail $true -MailTenantId "mytenant.onmicrosoft.com" -MailAppId "b4641624-1647-4d7e-a7bf-80f9a48b772b" -MailAppSecret "MySecrets" -MailFrom "dsc@contoso.com" -MailTo "admins@contoso.com"

.EXAMPLE
    .\CheckDscCompliance.ps1 -UseTeams $true -TeamsWebhook "https://teams.microsoft.com/webhook/123456"
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [System.Boolean]
    $UseMail = $false,

    [Parameter()]
    [AllowEmptyString()]
    [AllowNull()]
    [System.String]
    $MailTenantId = '',

    [Parameter()]
    [AllowEmptyString()]
    [AllowNull()]
    [System.String]
    $MailAppId = '',

    [Parameter()]
    [AllowEmptyString()]
    [AllowNull()]
    [System.String]
    $MailAppSecret = '',

    [Parameter()]
    [AllowEmptyString()]
    [AllowNull()]
    [System.String]
    $MailFrom = '',

    [Parameter()]
    [AllowEmptyString()]
    [AllowNull()]
    [System.String]
    $MailTo = '',

    [Parameter(Mandatory)]
    [System.Boolean]
    $UseTeams = $false,

    [Parameter()]
    [AllowEmptyString()]
    [AllowNull()]
    [System.String]
    $TeamsWebhook = ''
)

######## SCRIPT VARIABLES ########

$workingDirectory = $PSScriptRoot

$encounteredError = $false

######## START SCRIPT ########

$functionPath = Join-Path -Path $workingDirectory -ChildPath 'SupportFunctions.psm1'
try
{
    Import-Module -Name $functionPath -ErrorAction Stop
}
catch
{
    Write-Host "ERROR: Could not load library 'SupportFunctions.psm1'. $($_.Exception.Message.Trim('.')). Exiting." -ForegroundColor Red
    exit -1
}


Write-Log -Object '*********************************************************'
Write-Log -Object '*       Starting Microsoft365DSC Compliance Check       *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
if ($UseMail -eq $false -and $UseTeams -eq $false)
{
    Write-Log -Object '[ERROR] Both UseTeams and UseMail are set to False.' -Failure
    Write-Log -Object 'Please configure a notification method before continuing!' -Failure
    Write-Host '##vso[task.complete result=Failed;]Failed'
    exit 20
}

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Testing compliance on all environments'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
Write-Log -Object "Processing all MOF files in '$workingDirectory'"

$mofFiles = Get-ChildItem -Path $workingDirectory -Filter *.mof -Recurse
Write-Log -Object "- Found $($mofFiles.Count) MOF files"

$checkResults = @{}
foreach ($file in $mofFiles)
{
    $envName = Split-Path -Path $file.DirectoryName -Leaf
    Write-Log -Object "Processing environment: $envName"

    $checkResults.$envName = @{}

    try
    {
        $result = Test-DscConfiguration -ReferenceConfiguration $file.FullName -Verbose -ErrorAction Stop

        if ($result.InDesiredState -eq $false)
        {
            $checkResults.$envName.ErrorCount = $result.ResourcesNotInDesiredState.Count
            $checkResults.$envName.ErroredResources = $result.ResourcesNotInDesiredState.ResourceId -join ', '
        }
        else
        {
            $checkResults.$envName.ErrorCount = 0
            $checkResults.$envName.ErroredResources = ''
        }
    }
    catch
    {
        $checkResults.$envName.ErrorCount = 999
        $checkResults.$envName.ErroredResources = $_.Exception.Message
        $encounteredError = $true
        Write-Log -Object "[ERROR] An error occurred during DSC Compliance check: $($_.Exception.Message)" -Failure
    }
}

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Creating report'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
$htmlReport = '<!DOCTYPE html>'
$htmlReport += '<html>'
$htmlReport += '<head>'
$htmlReport += '<title>DSC Compliance Report</title>'
$htmlReport += '<style>table { border: 1px solid black; border-collapse: collapse; } th, td { padding: 10px; text-align:center } th { background-color: #00A4EF; color: white } .failed {background-color: red;} .nocenter {text-align:left;}</style>'
$htmlReport += '</head><body>'

$date = Get-Date -Format 'yyyy-MM-dd'
$title = 'DSC Compliance Report ({0})' -f $date
$htmlReport += "<H1>$title</H1>"

[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
$datetime = Get-Date -Format 'ddd dd-MM-yyyy HH:mm'
$generatedAt = 'Generated at: {0}<br>' -f $datetime
$htmlReport += $generatedAt
$htmlReport += '<br>'

$errorCount = 0
$erroredEnvironment = @()
foreach ($result in $checkResults.GetEnumerator())
{
    if ($result.Value.ErrorCount -gt 0)
    {
        $errorCount++
        $erroredEnvironment += $result.Key
    }
}

$incompliantEnvs = 'Number of incompliant environments: {0}<br>' -f $errorCount
$htmlReport += $incompliantEnvs
$htmlReport += '<br>'

$htmlReport += '<H3>Environments</H3>'

$report = '<table>'
$report += '<tr><th>Environment</th><th>In Desired State</th><th>Error Count</th><th>Details</th></tr>'

foreach ($environment in $checkResults.GetEnumerator())
{
    if ($environment.Value.ErrorCount -gt 0)
    {
        $report += '<tr><td>{0}</td><td class=failed>False</td><td>{1}</td><td class=nocenter>{2}</td></tr>' -f $environment.Key, $environment.Value.ErrorCount, $environment.Value.ErroredResources
    }
    else
    {
        $report += '<tr><td>{0}</td><td>True</td><td>0</td><td class=nocenter>-</td></tr>' -f $environment.Key
    }
}
$report += '</table>'
$htmlReport += $report
$htmlReport += '<br>'

$htmlReport += '</body></html>'


Write-Log -Object 'Report created!'

if ($UseMail)
{
    Write-Log -Object ' '
    Write-Log -Object '-----------------------------------------------------'
    Write-Log -Object ' Sending report via email'
    Write-Log -Object '-----------------------------------------------------'
    Write-Log -Object ' '

    Write-Log -Object 'Full HTML report:'
    Write-Log -Object $htmlReport
    Write-Log -Object ' '

    # Construct URI and body needed for authentication
    Write-Log -Object 'Retrieving Authentication Token'
    $uri = "https://login.microsoftonline.com/$MailTenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $MailAppId
        scope         = 'https://graph.microsoft.com/.default'
        client_secret = $MailAppSecret
        grant_type    = 'client_credentials'
    }

    $tokenRequest = Invoke-WebRequest -Method Post -Uri $uri -ContentType 'application/x-www-form-urlencoded' -Body $body -UseBasicParsing

    # Unpack Access Token
    $token = ($tokenRequest.Content | ConvertFrom-Json).access_token
    $Headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $token"
    }

    # Create message body and properties and send
    Write-Log -Object 'Creating email object'
    $MessageParams = @{
        'URI'         = "https://graph.microsoft.com/v1.0/users/$MailFrom/sendMail"
        'Headers'     = $Headers
        'Method'      = 'POST'
        'ContentType' = 'application/json'
        'Body'        = (@{
                'message' = @{
                    'subject'      = "DSC Compliance Report ($date)"
                    'body'         = @{
                        'contentType' = 'HTML'
                        'content'     = $htmlReport
                    }
                    'toRecipients' = @(
                        @{
                            'emailAddress' = @{'address' = $MailTo }
                        }
                    )
                }
            } | ConvertTo-Json -Depth 6 | Format-Json)
    }

    try
    {
        Write-Log -Object 'Trying to send mail'
        Invoke-RestMethod @Messageparams
        Write-Log -Object 'Report sent!'
    }
    catch
    {
        Write-Log -Object "[ERROR] Error while sending email message: $($_.Exception.Message)" -Failure
        Write-Log -Object '        Make sure you have configured the App Credentials and the From / To email addresses correctly!' -Failure
        $encounteredError = $true
    }
}

if ($UseTeams)
{
    # Documentation for Teams Message Card: https://docs.microsoft.com/en-us/microsoftteams/platform/task-modules-and-cards/cards/cards-reference#example-of-an-office-365-connector-card

    Write-Log -Object ' '
    Write-Log -Object '-----------------------------------------------------'
    Write-Log -Object ' Sending report via Teams'
    Write-Log -Object '-----------------------------------------------------'
    Write-Log -Object ' '

    Write-Log -Object 'Teams HTML message:'
    Write-Log -Object $report
    Write-Log -Object ' '

    if ($errorCount -gt 0)
    {
        # An error occurred during a check
        $themeColor = 'FF0000'
        $activityTitle = 'Check(s) failed!'
        $imageUrl = 'https://cdn.pixabay.com/photo/2012/04/12/13/15/red-29985_1280.png'
    }
    else
    {
        # All checks succeeded
        $themeColor = '0078D7'
        $activityTitle = 'All checks passed!'
        $imageUrl = 'https://cdn.pixabay.com/photo/2016/03/31/14/37/check-mark-1292787_1280.png'
    }

    $JSONBody = [PSCustomObject][Ordered]@{
        '@type'      = 'MessageCard'
        '@context'   = 'http://schema.org/extensions'
        'summary'    = $title
        'themeColor' = $themeColor
        'title'      = $title
        'sections'   = @(
            [PSCustomObject][Ordered]@{
                'activityTitle'    = $activityTitle
                'activitySubtitle' = $generatedAt
                'activityText'     = $incompliantEnvs
                'activityImage'    = $imageUrl
            },
            [PSCustomObject][Ordered]@{
                'title' = 'Details'
                'text'  = $report
            }
        )
    }

    $TeamMessageBody = ConvertTo-Json $JSONBody

    $parameters = @{
        'URI'         = $TeamsWebhook
        'Method'      = 'POST'
        'Body'        = $TeamMessageBody
        'ContentType' = 'application/json'
    }

    try
    {
        Write-Log -Object 'Trying to send Teams message'
        $restResult = Invoke-RestMethod @parameters
        if ($restResult -isnot [PSCustomObject] -or $restResult.isSuccessStatusCode -eq $false)
        {
            Write-Log -Object '[ERROR] Error while sending Teams message:'
            Write-Log -Object $restResult
            $encounteredError = $true
        }
        else
        {
            Write-Log -Object 'Report sent!'
        }
    }
    catch
    {
        Write-Log -Object "[ERROR] Error while sending Teams message: $($_.Exception.Message)" -Failure
        $encounteredError = $true
    }
}

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Saving Logs'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
$exportPath = Join-Path -Path $workingDirectory -ChildPath 'Logs'
if (Test-Path -Path $exportPath)
{
    Remove-Item -Path $exportPath -Recurse -Force
}

$null = New-Item -Path $exportPath -ItemType Directory -Force

$logs = @(
    @{
        LogName = 'M365DSC'
        FileName = 'M365DSC_Log.txt'
    }
    @{
        LogName = 'Microsoft-Windows-DSC/Operational'
        FileName = 'DSCOperational_Log.txt'
    }
    @{
        LogName = 'MSCloudLoginAssistant'
        FileName = 'MSCloudLoginAssistant_Log.txt'
    }
)

foreach ($log in $logs)
{
    Write-Log -Object "Processing log: $($log.LogName)"
    if ([System.Diagnostics.EventLog]::Exists($log.LogName))
    {
        $exportFile = Join-Path -Path $exportPath -ChildPath $log.FileName
        Get-WinEvent -LogName $log.LogName | Select-Object -Property RecordId,Id, MachineName, LevelDisplayName, ProviderName, TimeCreated, Message | Out-File -FilePath $exportFile -Encoding utf8
        Write-Log -Object "  Log successfully exported: $exportFile"
    }
    else
    {
        Write-Log -Object "  [SKIPPED] Log not found"
    }
}

Write-Log -Object '---------------------------------------------------------'
if ($encounteredError -eq $false -and $errorCount -eq 0)
{
    Write-Log -Object ' RESULT: Compliance check succeeded!'
}
else
{
    Write-Log -Object ' RESULT: Compliance check failed!' -Failure
    Write-Log -Object ' Issues found during compliance check!' -Failure
    Write-Log -Object ' Make sure you correct all issues and try again.' -Failure
    if ($errorCount -gt 0)
    {
        Write-Log -Object ' ' -Failure
        Write-Log -Object " Environments with errors: $($errorCount) ($($erroredEnvironment -join ', '))" -Failure
    }
}
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
Write-Log -Object '*********************************************************'
Write-Log -Object '*       Finished Microsoft365DSC Compliance Check       *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
