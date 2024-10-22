
#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Compiles the DSC MOF files, based on the Basic and Environment-specific data files.

.DESCRIPTION
    This script compiles the DSC MOF files and it uses the Basic and Environment-specific
    data files as input data. The script also performs quality checks on the data files,
    to make sure the data is correct and valid.

.EXAMPLE
    .\build.ps1
#>

[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
[CmdletBinding()]
param
(

)

######## SCRIPT VARIABLES ########

$workingDirectoryCICD = $PSScriptRoot
$workingDirectoryData = Join-Path -Path $workingDirectoryCICD -ChildPath '..\..\Data' -Resolve
$dataFilesFolder = Join-Path -Path $workingDirectoryData -ChildPath '\DataFiles'
$encounteredErrors = $false

######## START SCRIPT ########

try
{
    Import-Module -Name (Join-Path -Path $workingDirectoryCICD -ChildPath 'SupportFunctions.psm1') -ErrorAction Stop
}
catch
{
    Write-Host "ERROR: Could not load library 'SupportFunctions.psm1'. $($_.Exception.Message.Trim('.')). Exiting." -ForegroundColor Red
    exit -1
}

Write-Log -Object '*********************************************************'
Write-Log -Object '*   Starting Microsoft365DSC PostBuild steps            *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
Write-Log -Object "Switching to path: $workingDirectoryData"
Set-Location -Path $workingDirectoryData

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Changing to the source branch'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
Write-Log -Object "Switching to path: $($env:BUILD_SOURCEBRANCHNAME)"
git remote update *> $null
git fetch *> $null
git checkout --track origin/$($env:BUILD_SOURCEBRANCHNAME) -q *> $null

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Retrieving last commit information'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
$name = $env:BUILD_REQUESTEDFOR
$email = $env:BUILD_REQUESTEDFOREMAIL

Write-Log -Object 'Last commit created by:'
Write-Log -Object "Name : $name"
Write-Log -Object "Email: $email"
Write-Log -Object 'Using this information to commit the updates to the repository.'

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Processing Environment Information'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
Write-Log -Object 'Retrieving Environment Generic information'
$envInfo = Get-EnvironmentsGenericInfo -Path (Join-Path -Path $dataFilesFolder -ChildPath 'Environments')
Write-Log -Object ' '

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Updating pipeline Yaml file with environment information'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
$yamlResult = Set-PipelineYaml `
    -YamlPath (Join-Path -Path $workingDirectoryData -ChildPath 'Pipelines\deployment.yml') `
    -EnvironmentsInfo $envInfo

if ($yamlResult -eq $true)
{
    Write-Log -Object "Changing directory to '$workingDirectoryData'"
    Set-Location -Path $workingDirectoryData

    Write-Log -Object 'Checking if yml files need to be committed to the repository'
    $status = git status -s
    if (($status | ForEach-Object { $_ -like '*.yaml' -or $_ -like '*.yml' }) -contains $true)
    {
        Write-Log -Object "Committing $($status.Count) file changes to the repository"
        git config --global user.email "$email"
        git config --global user.name "$name"

        git add *.yml *.yaml
        git commit -m 'Updated pipeline yaml files [skip ci]'
        git push #origin HEAD:main
    }
}
else
{
    Write-Log -Object 'Updating of pipeline YAML file failed. Exiting.' -Failure
    $encounteredErrors = $true
}

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' Updating Azure DevOps pipeline environments'
Write-Log -Object ' based on the environment information'
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
# Needs to have the "<Project> Build Service (<OrgName>)" account added to the Project Administrators group in the project.

$approvers = @{}
foreach ($environment in $envInfo.GetEnumerator())
{
    $approvers.($environment.Key) = $environment.Value.Approvers
}

$adoResult = Set-ADOEnvironment `
    -Organization (Split-Path -Path $env:SYSTEM_COLLECTIONURI -Leaf) `
    -Project $env:SYSTEM_TEAMPROJECT `
    -TargetEnvironments $approvers.Keys `
    -Approvers $approvers `
    -DeploymentPipeline $env:BUILD_DEFINITIONNAME

if ($adoResult -eq $true)
{
    Write-Log -Object 'Updating of Azure DevOps pipeline environments completed successfully.'
}
else
{
    Write-Log -Object 'Updating of Azure DevOps pipeline environments failed. Exiting.' -Failure
    $encounteredErrors = $true
}

Write-Log -Object ' '
Write-Log -Object '---------------------------------------------------------'
if ($encounteredErrors)
{
    Write-Log -Object ' RESULT: Build script encountered errors!' -Failure
    Write-Host '##vso[task.complete result=Failed;]Failed'
}
else
{
    Write-Log -Object ' RESULT: Build script completed successfully!'
}
Write-Log -Object '---------------------------------------------------------'
Write-Log -Object ' '
Write-Log -Object '*********************************************************'
Write-Log -Object '*   Finished Microsoft365DSC Configuration Compilation  *'
Write-Log -Object '*********************************************************'
Write-Log -Object ' '
