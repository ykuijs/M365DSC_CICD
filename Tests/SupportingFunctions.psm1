function Test-IsUTF8WithBOM
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(ValueFromPipeline = $true)]
        $Path
    )

    process
    {
        if ((Test-Path -Path $Path) -eq $false)
        {
            Write-Host "Provided Path '$Path' does not exist!" -ForegroundColor Red
            return
        }
        else
        {
            $Path = (Resolve-Path $Path).Path
        }

        $Reader = [System.IO.StreamReader]::new($Path, [System.Text.Encoding]::GetEncoding('ISO-8859-1'), $True)
        [Void] $Reader.Peek()
        $currentEncoding = $Reader.CurrentEncoding
        $Reader.Close()
        return ($currentEncoding -is [System.Text.UTF8Encoding])
    }
}
