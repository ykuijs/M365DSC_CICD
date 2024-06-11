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
    Write-Log -Object '---------------------------------------------------------'
    Write-Log -Object ' '
    Write-Log -Object '*********************************************************'
    Write-Log -Object '*   Finished Microsoft365DSC Configuration Deployment   *'
    Write-Log -Object '*********************************************************'
    Write-Log -Object ' '
}
