BeforeDiscovery {
    $workingDirectoryCICD = $PSScriptRoot
    $rootDirectoryCICD = Split-Path -Path (Split-Path -Path $workingDirectoryCICD -Parent) -Parent
    $rootDirectoryData = Join-Path -Path (Split-Path -Path $rootDirectoryCICD -Parent) -ChildPath 'Data'
    $dataFilesPath = Join-Path -Path $rootDirectoryData -ChildPath 'DataFiles' -Resolve
    $envDataFilesPath = Join-Path -Path $dataFilesPath -ChildPath 'Environments' -Resolve

	# If there is no DataFiles folder, exit.
	if (-not (Test-Path -Path $dataFilesPath))
	{
		Write-Error 'DataFiles path not found!'
		return
	}

	$dataFiles = @(Get-ChildItem -Path $dataFilesPath -Filter '*.psd1' -Recurse)

	$dataFilesToTest = @()

	foreach ($datafile in $dataFiles)
	{
		$dataFilesToTest += @{
			DataFile                = $dataFile.FullName
			DataFileDescriptiveName = Join-Path -Path (Split-Path $dataFile.Directory -Leaf) -ChildPath (Split-Path $dataFile -Leaf)
		}
	}

    $envFiles = Get-ChildItem -Path $envDataFilesPath -File -Recurse -Include *.psd1
    $allEnvFileName = $envFiles | ForEach-Object { @{ BaseName = $_.BaseName; FolderName = $_.Directory.Name } }

    $filesInDataRepo = @()
    $items = Get-ChildItem -Path $rootDirectoryData -Exclude ".git*","Supportscripts",".vscode*" | Get-ChildItem -Recurse -File
    foreach ($item in $items)
    {
        $filesInDataRepo += @{
            FullName = $item.FullName
            Name     = $item.Name
        }
    }

    $filesInCICDRepo = @()
    $items = Get-ChildItem -Path $rootDirectoryCICD -Exclude ".git*","Supportscripts",".vscode*" | Foreach-Object { Get-ChildItem -Path $_.FullName -Recurse -File -Exclude "*.dll*" }
    foreach ($item in $items)
    {
        $filesInCICDRepo += @{
            FullName = $item.FullName
            Name     = $item.Name
        }
    }
}

Describe 'Check if all data files are valid' {
	It 'Check if import of data file <DataFileDescriptiveName> is successful' -TestCases $dataFilesToTest {
        { Import-PSDataFile -Path $DataFile } | Should -Not -Throw
	}
}

Describe 'Check if all files have the correct encoding' {
	It 'Check if encoding of <Name> in Data is UTF8 with BOM' -TestCases $filesInDataRepo {
        (Test-IsUTF8WithBOM -Path $FullName) | Should -Be $true
	}

    It 'Check if encoding of <Name> in CICD is UTF8 with BOM' -TestCases $filesInCICDRepo {
        (Test-IsUTF8WithBOM -Path $FullName) | Should -Be $true
	}
}

Describe 'Check if all Environment specific files follow the naming standard' {
	It 'Check if <BaseName>.psd1 has the correct naming' -TestCases $allEnvFileName {
        ($BaseName -split '#')[0] | Should -Be $FolderName
	}
}

Describe 'Check DSC Composite Resources in module M365DSC.CompositeResources' {
	BeforeAll {
		$configModule = Get-Module -Name M365DSC.CompositeResources -ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1
		$moduleFolder = Split-Path -Path $configModule.Path -Parent
		$resourcesInModule = Get-ChildItem -Path (Join-Path -Path $moduleFolder -ChildPath 'DSCResources') -Directory
		$resourcesFoundByDSC = Get-DscResource -Module 'M365DSC.CompositeResources'
	}

	It 'Number of resources in module should match number of resources found by DSC' {
		$resourcesFoundByDSC.Count | Should -Be $resourcesInModule.Count
	}
}
