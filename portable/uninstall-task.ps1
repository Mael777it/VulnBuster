# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
<# Zatrzymuje i usuwa zadanie VulnBuster oraz skrót z pulpitu. Dane w data\ pozostają nietknięte. #>
$ErrorActionPreference = "Stop"
if (Get-ScheduledTask -TaskName "VulnBuster" -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName "VulnBuster" -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "VulnBuster" -Confirm:$false
    Write-Host "Usunięto zadanie VulnBuster"
}
$lnk = Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "VulnBuster.url"
if (Test-Path $lnk) { Remove-Item $lnk }
Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -like "*$PSScriptRoot*run.py*" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force; Write-Host "Zatrzymano proces $($_.ProcessId)" }
