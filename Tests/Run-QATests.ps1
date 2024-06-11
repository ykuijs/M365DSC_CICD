#Requires -Modules Pester

$functionsModule = Join-Path -Path $PSScriptRoot -ChildPath 'SupportingFunctions.psm1'
Import-Module $functionsModule

$Params = [ordered]@{
    Path = (Join-Path -Path $PSScriptRoot -ChildPath 'QA\QualityAssurance.Tests.ps1')
}

$Container = New-PesterContainer @Params

$Configuration = [PesterConfiguration]@{
    Run    = @{
        Container = $Container
        PassThru  = $true
    }
    Output = @{
        Verbosity = 'Detailed'
    }
}

$result = Invoke-Pester -Configuration $Configuration

return $result
