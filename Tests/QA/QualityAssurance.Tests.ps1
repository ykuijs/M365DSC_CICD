BeforeDiscovery {
    $workingDirectoryCICD = $PSScriptRoot
    $rootDirectoryCICD = Split-Path -Path (Split-Path -Path $workingDirectoryCICD -Parent) -Parent
    $rootDirectoryData = Join-Path -Path (Split-Path -Path $rootDirectoryCICD -Parent) -ChildPath 'Data'
    $dataFilesPath = Join-Path -Path $rootDirectoryData -ChildPath 'DataFiles' -Resolve

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

    $filesInDataRepo = @()
    $items = Get-ChildItem -Path $rootDirectoryData -Recurse -File -Exclude ".git*" | Where-Object { $_.DirectoryName -notlike '*.vscode*' }
    foreach ($item in $items)
    {
        $filesInDataRepo += @{
            FullName = $item.FullName
            Name     = $item.Name
        }
    }

    $filesInCICDRepo = @()
    $items = Get-ChildItem -Path $rootDirectoryCICD -Recurse -File -Exclude ".git*" | Where-Object { $_.DirectoryName -notlike '*.vscode*' }
    foreach ($item in $items)
    {
        $filesInCICDRepo += @{
            FullName = $item.FullName
            Name     = $item.Name
        }
    }
}

Describe 'Check if all data files are valid' {
	It 'Import of data file <DataFileDescriptiveName> is successful' -TestCases $dataFilesToTest {
        $content = Get-Content -Path $DataFile -Raw
        $data = [Scriptblock]::Create($content)
        #$data = Import-PowerShellDataFile -Path $DataFile -ErrorAction SilentlyContinue
		$data | Should -Not -BeNullOrEmpty
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
