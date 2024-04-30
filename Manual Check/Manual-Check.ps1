Clear-Host
Write-Host 'Microsoft IIS 10.0 Server Security Technical Implementation Guide' -ForegroundColor Cyan
Write-Host 'Version 2, Release: 10 Benchmark Date: 25 Oct 2023' -ForegroundColor Cyan

Write-Host 'Loading STIG checks from:'
Write-Host (Get-Item -Path .\Enabled).FullName
[System.Collections.Generic.List[System.IO.FileInfo]] $EnabledChecks = Get-ChildItem -Path .\Enabled
Write-Host "$($EnabledChecks.Count) check loaded."
Write-Host
Write-Host 'Performing checks...' -ForegroundColor Yellow

ForEach ($EnabledCheck In $EnabledChecks)
{
    [String] $CheckName = $EnabledCheck.Name.Substring($EnabledChecks[0].Name.IndexOf('- ') + 2).trimend('.ps1')
    Write-Host $CheckName.PadRight(60) -NoNewline
    $ErrorActionPreference = 'Stop'
    Try
    {
        If (Invoke-Command -ScriptBlock (Get-Command ".\Enabled\$($EnabledCheck.Name)" | Select-Object -ExpandProperty ScriptBlock))
            { Write-Host 'Passed' -ForegroundColor Green }
        Else
            { Write-Host 'Failed' -ForegroundColor Red }
    }
    Catch
        { Write-Host 'Error' -ForegroundColor Yellow }
    $ErrorActionPreference = 'Continue'
}