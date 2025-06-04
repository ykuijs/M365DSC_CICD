function Write-Log
{
    <#
    .SYNOPSIS
        Dispatches log information

    .DESCRIPTION
        Write log information to the console so that it can be picked up by the deployment system
        The information written to the (host) display uses the following format:

        yyyy-MM-dd HH:mm:ss [Labels[]]<ScriptName>: <Message>

        Where:
        * yyyy-MM-dd HH:mm:ss is the sortable date/time where the log entry occurred
        * [Labels[]] represents one or more of the following colored labels:
            [ERROR]
            [FAILURE]
            [WARNING]
            [INFO]
            [DEBUG]
            [VERBOSE]
            [WHATIF]
            Note that each label could be combined with another label except for the [ERROR] and [FAILURE]
            which are exclusive and the [INFO] label which only set if none of the other labels applies
            (See also the -Warning and -Failure parameter)
        * <ScriptName> represents the script that called this Write-Log cmdlet
        * <Message> is a string representation of the -Object parameter
            Note that if the -Object contains an [ErrorRecord] type, the error label is set and the error
            record is output in a single line:

            at <LineNumber> char:<Offset> <Error Statement> <Error Message>

            Where:
            * <LineNumber> represents the line where the error occurred
            * <Offset> represents the offset in the line where the error occurred
            * <Error Statement> represents the statement that caused the error
            * <error message> represents the description of the error

    .PARAMETER Object
        Writes the object as a string to the host from a script or command.
        If the object is of an [ErrorRecord] type, the [ERROR] label will be added and the error
        name and position are written to the host from a script or command unless the $ErrorPreference
        is set to SilentlyContinue.

    .PARAMETER Warning
        Writes warning messages to the host from a script or command unless the $WarningPreference
        is set to SilentlyContinue.

    .PARAMETER Failure
        Writes failure messages to the host from a script or command unless the $ErrorPreference
        is set to SilentlyContinue.

        Note that the common parameters -Debug and -Verbose have a simular behavor as the -Warning
        and -Failure Parameter and will not be shown if the corresponding $<name>preference variable
        is set to 'SilentlyContinue'.

    .PARAMETER Path
        The path to a log file. If set, all the output is also sent to a log file for all the following
        log commands. Use an empty path to stop file logging for the current session: `-Path ''`

        Note that environment variables (as e.g. '%Temp%\My.Log') are expanded.

    .PARAMETER Tee
        Logs (displays) the output and also sends it down the pipeline.

    .PARAMETER WriteActivity
        By default, the current activity (message) is only exposed (using the Write-Progress cmdlet)
        when it is invoked from the deployment system. This switch (-WriteActivity or -WriteActivity:$False)
        will overrule the default behavior.

    .PARAMETER WriteEvent
        When set, this cmdlet will also write the message to the Windows Application EventLog.
        Where:
        * If the [EventSource] parameter is ommited, the Source will be "Automation"
        * The Category represents the concerned labels:
            Info    = 0
            Verbose = 1
            Debug   = 2
            WhatIf  = 4
            Warning = 8
            Failure = 16
            Error   = 32
        * The Message is a string representation of the object
        * If [EventId] parameter is ommited, the EventID will be a 32bit hashcode based on the message
        * EventType is "Error" in case of an error or when the -Failure parameter is set,
            otherwise "Warning" if the -Warning parameter is set and "Information" by default.

        Note 1: logging Windows Events, requires elevated rights if the event source does not yet exist.
        Note 2: This parameter is not required if the [EventSource] - or [EventId] parameter is supplied.

    .PARAMETER EventSource
        When defined, this cmdlet will also write the message to the given EventSource in the
        Windows Application EventLog. For details see the [WriteEvent] parameter.

    .PARAMETER EventId
        When defined, this cmdlet will also write the message Windows Application EventLog using the
        specified EventId. For details see the [WriteEvent] parameter.

    .PARAMETER Type
        This parameter will show if the log information is from type INFO, WARNING or Error.
        * Warning: this parameter is depleted, use the corresponding switch as e.g. `-Warning`.

    .PARAMETER Message
        This parameter contains the message that wil be shown.
        * Warning: this parameter is depleted, use the `-Object` parameter instead.

    .PARAMETER Logpath
        This parameter contains the log file path.
        * Warning: this parameter is depleted, use the `-Path` parameter instead.

    .EXAMPLE
        # Log a message

        Displays the following entry and updates the progress activity in the deployment system:

            Write-Log 'Deploying VM'
            2022-08-10 11:56:12 [INFO] MyScript: Deploying VM

    .EXAMPLE
        # Log and save a warning

        Displays `File not found` with a `[WARNING]` as shown below, updates the progress activity
        in the deployment system. Besides, it writes the warning to the file: c:\temp\log.txt and
        create and add an entry to the EventLog.

            Write-Log -Warning 'File not found' -Path c:\temp\log.txt -WriteEvent
            2022-08-10 12:03:51 [WARNING] MyScript: File not found

    .EXAMPLE
        # Log and capture a message

        Displays `my message` as shown below and capture the message in the `$Log` variable.

            $Log = Write-Log 'My message' -Tee
            2022-08-10 12:03:51 [INFO] MyScript: File not found
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '')]
    [CmdletBinding(DefaultParameterSetName = 'Warning')]
    param
    (
        [Parameter(ParameterSetName = 'Warning', Position = 0, ValueFromPipeline = $true)]
        [Parameter(ParameterSetName = 'Failure', Position = 0, ValueFromPipeline = $true)]
        $Object,

        [Parameter(ParameterSetName = 'Warning')]
        [switch] $Warning,

        [Parameter(ParameterSetName = 'Failure')]
        [switch] $Failure,

        [Parameter(ParameterSetName = 'Warning')]
        [Parameter(ParameterSetName = 'Failure')]
        [string] $Path,

        [Parameter(ParameterSetName = 'Warning')]
        [Parameter(ParameterSetName = 'Failure')]
        [switch] $WriteActivity,

        [Parameter(ParameterSetName = 'Warning')]
        [Parameter(ParameterSetName = 'Failure')]
        [switch] $WriteEvent,

        [Parameter(ParameterSetName = 'Warning')]
        [Parameter(ParameterSetName = 'Failure')]
        [string] $EventSource = 'Automation',

        [Parameter(ParameterSetName = 'Warning')]
        [Parameter(ParameterSetName = 'Failure')]
        [int] $EventId = -1,

        [Parameter(ParameterSetName = 'Warning')]
        [Parameter(ParameterSetName = 'Failure')]
        [switch] $Tee,

        [Parameter(ParameterSetName = 'Legacy', Position = 0, Mandatory = $true)]
        [Validateset('INFO', 'WARNING', 'ERROR', 'DEBUG')]
        [Alias('LogType')][string] $Type,

        [Parameter(ParameterSetName = 'Legacy', Position = 1, Mandatory = $true)]
        [string]$Message,

        [Parameter(ParameterSetName = 'Legacy')]
        [Alias('LogPath')][string] $FilePath
    )

    begin
    {
        if (!$Global:WriteLog)
        {
            $Global:WriteLog = @{}
        }

        $PSCallStack = Get-PSCallStack
        $Commands = @($PSCallStack.Command)
        $Me = $Commands[0]
        $Caller = if ($Commands -gt 1)
        {
            $Commands[1..($Commands.Length)].where({ $_ -ne $Me }, 'First')
        }
        if (!$Caller)
        {
            $Caller = ''
        } # Prevent that the array index evaluates to null.
        $MeAgain = $Commands -gt 2 -and $Commands[2] -eq $Me

        if (!$Global:WriteLog.Contains($Caller))
        {
            # if ($PSCmdlet.ParameterSetName -eq 'Legacy') {
            #     Write-Log -Warning "Use the new implementation: $($MyInvocation.MyCommand) [-Warning|-Failure] 'message'"
            # }
            $Global:WriteLog[$Caller] = @{}
        }

        if ($PSCmdlet.ParameterSetName -eq 'Legacy')
        {

            switch ($Type)
            {
                'INFO'
                {
                    $TypeColor = 'Green'; $ThrowError = $false
                }
                'WARNING'
                {
                    $TypeColor = 'Yellow'; $ThrowError = $false
                }
                'DEBUG'
                {
                    $TypeColor = 'Cyan'; $ThrowError = $false
                }
                'ERROR'
                {
                    $TypeColor = 'Red'; $ThrowError = $true
                }
            }

            $ChunksEntry = $(Get-Date -Format '[dd-MM-yyyy][HH:mm:ss]') + $('[' + $Type.padright(7) + '] ')

            # Exit script if "$Type -eq "DEBUG" -and $VerbosePreference -eq "SilentlyContinue"
            if ($Type -eq 'DEBUG' -and $VerbosePreference -eq 'SilentlyContinue')
            {
                return
            }

            Write-Host $ChunksEntry -ForegroundColor $TypeColor -NoNewline
            if ($ThrowError)
            {
                Write-Error $Message
            }
            else
            {
                Write-Host $Message
            }

            if ($FilePath)
            {
                Try
                {
                    $($ChunksEntry + $Message) | Out-File -FilePath $FilePath -Append
                }
                Catch
                {
                    Write-Log -Warning "Can not write to logfile $FilePath"
                }
            }
        }
        else
        {
            [Flags()] enum EventFlag
            {
                Info = 0
                Verbose = 1
                Debug = 2
                WhatIf = 4
                Warning = 8
                Failure = 16
                Error = 32
            }

            $IsVerbose = $PSBoundParameters.Verbose.IsPresent
            $VerboseMode = $IsVerbose -and $PSCmdlet.SessionState.PSVariable.Get('VerbosePreference').Value -ne 'SilentlyContinue'

            $IsDebug = $PSBoundParameters.Debug.IsPresent
            $DebugMode = $IsDebug -and $PSCmdlet.SessionState.PSVariable.Get('DebugPreference').Value -ne 'SilentlyContinue'

            $WhatIfMode = $PSCmdlet.SessionState.PSVariable.Get('WhatIfPreference').Value

            $WriteEvent = $WriteEvent -or $PSBoundParameters.ContainsKey('EventSource') -or $PSBoundParameters.ContainsKey('EventID')
            if ($PSBoundParameters.ContainsKey('Path'))
            {
                $Global:WriteLog[$Caller].Path = [System.Environment]::ExpandEnvironmentVariables($Path)
            } # Reset with: -Path ''
        }

        function WriteLog
        {
            if ($Failure -and !$Object)
            {
                $Object = if ($Error.Count)
                {
                    $Error[0]
                }
                else
                {
                    '<No error found>'
                }
            }

            $IsError = $Object -is [System.Management.Automation.ErrorRecord]

            $Category = [EventFlag]::new(); $EventType = 'Information'
            if ($ErrorPreference -ne 'SilentlyContinue' -and $IsError)
            {
                $Category += [EventFlag]::Error
            }
            if ($ErrorPreference -ne 'SilentlyContinue' -and $Failure)
            {
                $Category += [EventFlag]::Failure
            }
            if ($WarningPreference -ne 'SilentlyContinue' -and $Warning)
            {
                $Category += [EventFlag]::Warning
            }
            if ($IsDebug)
            {
                $Category += [EventFlag]::Debug
            }
            if ($IsVerbose)
            {
                $Category += [EventFlag]::Verbose
            }
            if ($WhatIfMode)
            {
                $Category += [EventFlag]::WhatIf
            }
            $IsInfo = !$Category

            $ColorText = [System.Collections.Generic.List[HashTable]]::new()
            $ColorText.Add( @{ Object = Get-Date -Format 'yyyy-MM-dd HH:mm:ss ' } )

            if ($IsError)
            {
                $ColorText.Add(@{ BackgroundColor = 'Red'; ForegroundColor = 'Black'; Object = '[ERROR]' })
            }
            elseif ($Failure)
            {
                $ColorText.Add(@{ BackgroundColor = 'Red'; ForegroundColor = 'Black'; Object = '[FAILURE]' })
            }
            if ($Warning)
            {
                $ColorText.Add(@{ BackgroundColor = 'Yellow'; ForegroundColor = 'Black'; Object = '[WARNING]' })
            }
            if ($IsInfo)
            {
                $ColorText.Add(@{ BackgroundColor = 'Green'; ForegroundColor = 'Black'; Object = '[INFO]' })
            }
            if ($IsDebug)
            {
                $ColorText.Add(@{ BackgroundColor = 'Cyan'; ForegroundColor = 'Black'; Object = '[DEBUG]' })
            }
            if ($IsVerbose)
            {
                $ColorText.Add(@{ BackgroundColor = 'Blue'; ForegroundColor = 'Black'; Object = '[VERBOSE]' })
            }
            if ($WhatIfMode)
            {
                $ColorText.Add(@{ BackgroundColor = 'Magenta'; ForegroundColor = 'Black'; Object = '[WHATIF]' })
            }

            if ($Caller -and $Caller -ne '<ScriptBlock>')
            {
                $ColorText.Add( @{ Object = " $($Caller):" } )
            }

            $ColorText.Add( @{ Object = ' ' } )
            if ($IsError)
            {
                $Info = $Object.InvocationInfo
                $ColorText.Add(@{ BackgroundColor = 'Black'; ForegroundColor = 'Red'; Object = " $Object" })
                $ColorText.Add(@{ Object = " at $($Info.ScriptName) line:$($Info.ScriptLineNumber) char:$($Info.OffsetInLine) " })
                $ColorText.Add(@{ BackgroundColor = 'Black'; ForegroundColor = 'White'; Object = $Info.Line.Trim() })
            }
            elseif ($Failure)
            {
                $ColorText.Add(@{ ForegroundColor = 'Red'; Object = $Object; BackgroundColor = 'Black' })
            }
            elseif ($Warning)
            {
                $ColorText.Add(@{ ForegroundColor = 'Yellow'; Object = $Object })
            }
            elseif ($DebugMode)
            {
                $ColorText.Add(@{ ForegroundColor = 'Cyan'; Object = $Object })
            }
            elseif ($VerboseMode)
            {
                $ColorText.Add(@{ ForegroundColor = 'Green'; Object = $Object })
            }
            else
            {
                $ColorText.Add(@{ Object = $Object })
            }

            foreach ($ColorItem in $ColorText)
            {
                Write-Host -NoNewline @ColorItem
            }
            Write-Host # New line

            if ($Tee)
            {
                -Join $ColorText.Object
            }
            $Message = -Join $ColorText[1..99].Object # Skip the date/time
            if ($WriteActivity)
            {
                Write-Progress -Activity $Message
            }
            if ($WriteEvent)
            {
                $SourceExists = Try
                {
                    [System.Diagnostics.EventLog]::SourceExists($EventSource)
                }
                Catch
                {
                    $False
                }
                if (!$SourceExists)
                {
                    $WindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                    $WindowsPrincipal = [System.Security.Principal.WindowsPrincipal]::new($WindowsIdentity)
                    if ($WindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
                    {
                        New-EventLog -LogName 'Application' -Source $EventSource
                        $SourceExists = Try
                        {
                            [System.Diagnostics.EventLog]::SourceExists($EventSource)
                        }
                        Catch
                        {
                            $False
                        }
                    }
                    else
                    {
                        Write-Log -Warning "The EventLog ""$EventSource"" should exist or administrator rights are required"
                    }
                }
                if ($SourceExists)
                {
                    if ($EventID -eq -1)
                    {
                        $EventID = if ($Null -ne $Object)
                        {
                            "$Object".GetHashCode() -bAnd 0xffff
                        }
                        Else
                        {
                            0
                        }
                    }
                    $EventType =
                    if ($Category.HasFlag([EventFlag]::Error))
                    {
                        'Error'
                    }
                    elseif ($Category.HasFlag([EventFlag]::Failure))
                    {
                        'Error'
                    }
                    elseif ($Category.HasFlag([EventFlag]::Warning))
                    {
                        'Warning'
                    }
                    else
                    {
                        'Information'
                    }
                    Write-EventLog -LogName 'Application' -Source $EventSource -Category $Category -EventId $EventId -EntryType $EventType -Message $Message
                }
            }
            if ($Global:WriteLog[$Caller].Path)
            {
                Try
                {
                    Add-Content -Path $Global:WriteLog[$Caller].Path -Value (-Join $ColorText.Object)
                }
                Catch
                {
                    Write-Log -Warning "Can not write to logfile $FilePath"
                }
            }
        }
    }

    process
    {
        if ($PSCmdlet.ParameterSetName -ne 'Legacy' -and !$MeAgain)
        {
            if (!$IsVerbose -and !$IsDebug)
            {
                WriteLog
            }
            elseif ($VerboseMode)
            {
                WriteLog
            }
            elseif ($DebugMode)
            {
                WriteLog
            }
        }
    }
}

function Format-Json
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.String]
        $RawJson,

        [Parameter()]
        [System.String]
        $IndentString = "`t"
    )

    $indent = 0
    $json = ($RawJson -replace '(\{|\[)[\s]*?(\}|\])', "`$1`$2").Split([System.Environment]::NewLine, [System.StringSplitOptions]::RemoveEmptyEntries)
    $convJson = $json | ForEach-Object {
        $trimJson = $_.Trim()
        $line = ($IndentString * $indent) + $($trimJson -replace "`":\s+", "`": ")

        if ($trimJson -match '[^\{\[,]$')
        {
            # This line doesn't end with '{', '[' or ',', decrement the indentation level
            $indent--
        }

        if ($trimJson -match '^[\{\[]|[\{\[]$')
        {
            # This line starts or ends with '[' or '{', increment the indentation level
            $indent++
        }
        $line
    }
    $returnValue = $convJson -join [System.Environment]::NewLine
    $returnValue = [Regex]::Replace($returnValue, '(?<![\\])\\u(?<Value>[a-zA-Z0-9]{4})', {
            param($m) ([char]([int]::Parse($m.Groups['Value'].Value, [System.Globalization.NumberStyles]::HexNumber))).ToString()
        }
    )
    return $returnValue
}

function Install-GenericModules
{
    <#
	.Synopsis
	Installs all generic Microsoft365DSC supporting modules from PSGallery or a custom NuGet repository,
    using the ModuleFast module.

	.Description
	This function installs the latest versions of all supporting Microsoft365DSC generic modules
	from PSGallery or a custom NuGet package feed, except for the M365DSC.CompositeResources module, where
	it installs the latest version that corresponds the given Microsoft365DSC module version. It uses the
    ModuleFast module to install the modules.

    .Parameter TargetPath
	The path where the modules should be downloaded to.

	.Parameter PrerequisitesPath
	The path to the Prequisites file for this solution.

	.Parameter Version
	The version of the Microsoft365DSC module that is being used

	.Example
	Install-GenericModules -Version '1.23.1115.1'
	#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $TargetPath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $PrerequisitesPath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Version
    )

    Write-Log -Object "Required Microsoft365DSC Version: $Version"
    Write-Log -Object ' '
    Write-Log -Object "- Target Path: $TargetPath"
    Write-Log -Object ' '

    Write-Log -Object 'Querying required generic modules'
    $resourceModules = Import-PowerShellDataFile -Path $PrerequisitesPath
    $reqModules = [System.Collections.HashTable]::new($resourceModules)
    $reqModules.Remove('Microsoft365DSC')
    $resourceModules.GetEnumerator() | Where-Object { $_.Value -match '^$' } | ForEach-Object { $reqModules.Remove($_.Name) }
    Write-Log -Object "Found $($reqModules.Keys.Count) required generic module(s):"
    $maxLength = ($reqModules.Keys | Measure-Object -Maximum -Property Length).Maximum
    $reqModules.GetEnumerator() | ForEach-Object { Write-Log -Object ("* {0,-$maxLength} - {1}" -f $_.Key, $_.Value) }

    Write-Log -Object ' '
    Write-Log -Object 'Installing required generic modules'

    $oldProgressPreference = $progressPreference
    $progressPreference = 'SilentlyContinue'

    foreach ($module in $reqModules.Keys)
    {
        $moduleVersion = $reqModules.$module

        $parameters = @{
            Specification   = $module
            Destination     = $TargetPath
            Update          = $true
            NoProfileUpdate = $true
            DestinationOnly = $true
            PassThru        = $true
        }

        if ($moduleVersion -like '*preview*')
        {
            $parameters.Add('Prerelease', $true)
        }

        switch ($moduleVersion)
        {
            ''
            {
                continue
            }
            $null
            {
                continue
            }
            latest
            {
                continue
            }
            latestMatchingMicrosoft365DSC
            {
                $parameters.Specification += ":{0}*" -f $Version
            }
            Default
            {
                $parameters.Specification += "={0}" -f $moduleVersion
            }
        }

        Write-Log -Object "  Installing module '$($parameters.Specification)' ($($reqModules.$module))"
        [array]$results = Install-ModuleFast @parameters

        $installedModules = foreach ($result in $results) { "$($result.Name) ($($result.ModuleVersion))"}
        Write-Log -Object "    -> Installed: $($installedModules -join " / ")"
    }

    $progressPreference = $oldProgressPreference
}

function Initialize-PSGallery
{
    <#
	.Synopsis
	Configures the PowerShell Gallery as a trusted repository

	.Description
	This function configures the PowerShell Gallery as a trusted repository,
    so that modules can be installed from it without warnings or user interaction.

	.Example
	Initialize-PSGallery
	#>
    [CmdletBinding()]
    param ()

    Write-Log -Object 'Checking PowerShell Gallery repository configuration'
    $psGallery = Get-PSRepository PSGallery
    if ($psGallery.InstallationPolicy -ne 'Trusted')
    {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
    }
}

function Install-DSCModule
{
    <#
	.Synopsis
	Installs the Microsoft365DSC module from the PowerShell Gallery using ModuleFast

	.Description
	This function installs the Microsoft365DSC module from the PowerShell Gallery
    using the ModuleFast function.

    .Parameter TargetPath
	The path where the modules should be downloaded to.

	.Parameter PrerequisitesPath
	The path to the Prequisites file for this solution.

	.Parameter Version
	The version of the Microsoft365DSC module that is being used

	.Example
	Install-DSCModule -PrerequisitesPath "$PSScriptPath\DscResources.psd1"
	#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $TargetPath,

        [Parameter()]
        [System.String]
        $PrerequisitesPath,

        [Parameter()]
        [System.String]
        $Version
    )

    Write-Log -Object 'Checking Microsoft365DSC versions'
    if ($Version)
    {
        $reqVersion = $Version
    }
    else
    {
        if ($PSBoundParameters.ContainsKey('PrerequisitesPath'))
        {
            $reqVersion = Get-RequiredM365DSCVersion -PrerequisitesPath $PrerequisitesPath
        }
        else
        {
            Write-Log -Object '[ERROR] Neither Version of PrerequisitesPath parameters was specified. Exiting!' -Failure
            Write-Host '##vso[task.complete result=Failed;]Failed'
            exit 10
        }
    }
    $localModule = Get-Module -Name Microsoft365DSC -ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1

    Write-Log -Object "- Required version : $reqVersion"
    Write-Log -Object "- Installed version: $($localModule.Version)"

    Write-Log -Object ' '
    Write-Log -Object "- Target Path: $TargetPath"
    Write-Log -Object ' '

    if ($localModule.Version -ne $reqVersion)
    {
        if ($null -ne $localModule)
        {
            Write-Log -Object 'Incorrect version installed. Removing current module.'
            $m365ModulePath = Join-Path -Path "$($env:ProgramFiles)\WindowsPowerShell\Modules" -ChildPath 'Microsoft365DSC'
            Remove-Item -Path $m365ModulePath -Force -Recurse -ErrorAction SilentlyContinue
        }

        Initialize-PSGallery

        Write-Log -Object "Installing Microsoft365DSC v$reqVersion"
        $params = @{
            Specification   = 'Microsoft365DSC={0}' -f $reqVersion
            Destination     = $TargetPath
            Update          = $true
            NoProfileUpdate = $true
            DestinationOnly = $true
            PassThru        = $true
        }

        $oldProgressPreference = $progressPreference
        $progressPreference = 'SilentlyContinue'

        [array]$results = Install-ModuleFast @params

        $installedModules = foreach ($result in $results) { "$($result.Name) ($($result.ModuleVersion))"}
        Write-Log -Object "    -> Installed: $($installedModules -join " / ")"

        $progressPreference = $oldProgressPreference
    }
    else
    {
        Write-Log -Object 'Correct version installed, continuing.'
    }

    return $reqVersion
}

function Get-RequiredM365DSCVersion
{
    <#
	.Synopsis
	Retrieves the required version of the Microsoft365DSC module from the Prerequisites file

	.Description
	This function retrieves the required version of the Microsoft365DSC module from the Prerequisites file
    for this solution.

	.Parameter PrerequisitesPath
	The path to the Prequisites file for this solution.

    .Example
	Get-RequiredM365DSCVersion -PrerequisitesPath "$PSScriptPath\DscResources.psd1"
	#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter()]
        [System.String]
        $PrerequisitesPath
    )

    Write-Log -Object 'Checking Microsoft365DSC versions'
    if (Test-Path -Path $PrerequisitesPath)
    {
        $reqModules = Import-PowerShellDataFile -Path $PrerequisitesPath

        if (-not $reqModules.ContainsKey('Microsoft365DSC'))
        {
            Write-Log -Object '[ERROR] Unable to find Microsoft365DSC in DscResources.psd1. Exiting!' -Failure
            Write-Host '##vso[task.complete result=Failed;]Failed'
            exit 10
        }
        else
        {
            $reqVersion = $reqModules.Microsoft365DSC
            Write-Log -Object "- Required version: $reqVersion"
        }
    }
    else
    {
        Write-Log -Object "[ERROR] Unable to find '$PrerequisitesPath'. Exiting!" -Failure
        Write-Host '##vso[task.complete result=Failed;]Failed'
        exit 10
    }

    return $reqVersion
}

function Install-DSCModulePrereqs
{
    <#
	.Synopsis
	Installs all prerequisites for the Microsoft365DSC module using ModuleFast

	.Description
	This function installs all prerequisites for the Microsoft365DSC module using the ModuleFast function.

    .Parameter TargetPath
	The path where the modules should be downloaded to.

	.Parameter PrerequisitesPath
	The path to the Prequisites file for this solution.

	.Parameter Version
	The version of the Microsoft365DSC module that is being used

    .Example
	Install-DSCModulePrereqs -PrerequisitesPath "$PSScriptPath\DscResources.psd1"
	#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Write-Host needed for Azure DevOps logging')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $TargetPath,

        [Parameter()]
        [System.String]
        $PrerequisitesPath,

        [Parameter()]
        [System.String]
        $Version
    )

    Write-Log -Object 'Checking Microsoft365DSC versions'
    if ($Version)
    {
        $reqVersion = $Version
    }
    else
    {
        if ($PSBoundParameters.ContainsKey('PrerequisitesPath'))
        {
            $reqVersion = Get-RequiredM365DSCVersion -PrerequisitesPath $PrerequisitesPath
        }
        else
        {
            Write-Log -Object '[ERROR] Neither Version of PrerequisitesPath parameters was specified. Exiting!' -Failure
            Write-Host '##vso[task.complete result=Failed;]Failed'
            exit 10
        }
    }
    $localModule = Get-Module -Name Microsoft365DSC -ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1

    if ($null -eq $localModule)
    {
        Write-Log -Object "Microsoft365DSC not installed. Exiting!"
        return $null
    }

    Write-Log -Object "- Required version : $reqVersion"
    Write-Log -Object "- Installed version: $($localModule.Version)"

    Write-Log -Object ' '
    Write-Log -Object "- Target Path: $TargetPath"
    Write-Log -Object ' '

    $dependencyFile = Join-Path -Path (Split-Path -Path $localModule.Path -Parent) -ChildPath 'Dependencies\Manifest.psd1'
    if (Test-Path -Path $dependencyFile)
    {
        $dependencies = Import-PowerShellDataFile -Path $dependencyFile
        $moduleSpec = @()
        foreach ($dependency in ($dependencies.Dependencies | Where-Object { $_.PowerShellCore -ne $true }))
        {
            $module = $dependency.ModuleName
            $moduleVersion = $dependency.RequiredVersion

            Write-Log -Object "Adding module '$($module) ($($moduleVersion))' to download list"
            $moduleSpec += '{0}={1}' -f $module, $moduleVersion
        }

        Write-Log -Object "Installing all modules"
        $parameters = @{
            Specification   = $moduleSpec
            Destination     = $TargetPath
            Update          = $true
            NoProfileUpdate = $true
            DestinationOnly = $true
            PassThru        = $true
        }

        $oldProgressPreference = $progressPreference
        $progressPreference = 'SilentlyContinue'

        try
        {
            [array]$results = Install-ModuleFast @parameters
        }
        catch
        {
            Write-Log -Object "Error occurred during download: $($_.Exception.Message)" -Failure
            return $false
        }

        $installedModules = foreach ($result in $results) { "$($result.Name) ($($result.ModuleVersion))"}
        Write-Log -Object "    -> Installed: $($installedModules -join " / ")"

        $progressPreference = $oldProgressPreference

        if ($null -ne $results)
        {
            return $true
        }
        else
        {
            return $false
        }
    }
    else
    {
        Write-Log -Object "[ERROR] Unable to find dependency file '$dependencyFile'. Exiting!" -Failure
        Write-Host '##vso[task.complete result=Failed;]Failed'
        exit 10
    }
}
