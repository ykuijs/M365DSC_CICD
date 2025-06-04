#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Deploys the DSC configuration to the target environment.

.DESCRIPTION
    This script deploys the generated MOF file to the specified environment.

.PARAMETER Environment
    The environment to be deployed. This parameter is mandatory.

.EXAMPLE
    .\Deploy.ps1 -Environment 'Dev'
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
[CmdletBinding()]
param
(
    [Parameter(Mandatory = $true)]
    [System.String]
    $Environment
)

######## SCRIPT VARIABLES ########

$workingDirectory = $PSScriptRoot
$msCloudLoginAssistantDebug = $false

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
Write-Log -Object '*      Starting M365 DSC Configuration Deployment       *'
Write-Log -Object '*********************************************************'
Write-Log -Object "Environment to be deployed: $Environment"
Write-Log -Object '*********************************************************'
Write-Log -Object ' '

Write-Log -Object "Switching to path: $workingDirectory"
Set-Location -Path $workingDirectory

Write-Log -Object 'Checking for presence of the specified environment'
$environmentPath = Join-Path -Path $workingDirectory -ChildPath $Environment
if ((Test-Path -Path $environmentPath) -eq $false)
{
    Write-Error 'Specified environment not found'
    Write-Host '##vso[task.complete result=Failed;]Failed'
    Exit 20
}

if ($msCloudLoginAssistantDebug)
{
    Write-Log -Object ' '
    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' Enable MSCloudLoginAssistant Debug Mode'
    Write-Log -Object '---------------------------------------------------------'
    [Environment]::SetEnvironmentVariable('MSCLOUDLOGINASSISTANT_WRITETOEVENTLOG', 'true', 'Machine')
}

Write-Log -Object ' '
Write-Log -Object '----------------------------------------------------------------'
Write-Log -Object ' Removing all outdated versions of the dependencies'
Write-Log -Object '----------------------------------------------------------------'
Write-Log -Object ' '
# Removing all versions of the dependencies that are not used by Microsoft365DSC.
# This to prevent issues with the Microsoft365DSC module when the agents has other
# versions of the dependencies installed.
Uninstall-M365DSCOutdatedDependencies

try
{
    $deploymentSucceeded = $true
    Write-Log -Object ' '
    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' Running deployment of MOF file'
    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' '
    $Error.Clear()
    Start-DscConfiguration -Path $environmentPath -Verbose -Wait -Force
}
catch
{
    Write-Log -Object 'MOF Deployment Failed!'
    Write-Log -Object "Error occurred during deployment: $($_.Exception.Message)"
    $deploymentSucceeded = $false
}
finally
{
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
            Write-Log -Object "  Log successfully exported"
        }
        else
        {
            Write-Log -Object "  [SKIPPED] Log not found"
        }
    }

    Write-Log -Object ' '
    Write-Log -Object '---------------------------------------------------------'
    if ($deploymentSucceeded -eq $true -and $Error.Count -eq 0)
    {
        Write-Log -Object ' RESULT: MOF Deployment Succeeded!'
    }
    else
    {
        Write-Log -Object ' RESULT: MOF Deployment Failed!' -Failure
        Write-Log -Object ' Issues found during configuration deployment!' -Failure
        Write-Log -Object ' Make sure you correct all issues and try again.' -Failure

        if ($Error.Count -gt 0)
        {
            $count = 1
            $Error.Reverse()
            foreach ($err in $Error)
            {
                Write-Log -Object ('[{1}] Error message: {0}' -f $err.Exception.Message, $count.ToString('000')) -Failure
                Write-Log -Object ('[{1}] StackTrace: {0}' -f ($err.ScriptStackTrace -replace '\n', ' | '), $count.ToString('000')) -Failure
                $count++
            }
        }

        Write-Host '##vso[task.complete result=Failed;]Failed'
    }

    Write-Log -Object ' '
    Write-Log -Object '----------------------------------------------------------------'
    Write-Log -Object ' Removing the deployed configuration from the LCM'
    Write-Log -Object '----------------------------------------------------------------'
    Write-Log -Object ' '
    # This is to prevent issues in subsequent runs when using Self-Hosted agents
    Remove-DscConfigurationDocument -Stage 'Current', 'Pending', 'Previous' -Force

    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' '
    Write-Log -Object '*********************************************************'
    Write-Log -Object '*   Finished Microsoft365DSC Configuration Deployment   *'
    Write-Log -Object '*********************************************************'
    Write-Log -Object ' '
}
