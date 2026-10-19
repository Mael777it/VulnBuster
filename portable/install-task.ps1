# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
<#
.SYNOPSIS
  Instaluje VulnBuster jako zadanie uruchamiane przy starcie serwera (bez zależności od zalogowanego użytkownika).

.DESCRIPTION
  * Zadanie Harmonogramu "VulnBuster" startuje przy rozruchu systemu i restartuje się po awarii.
  * Domyślnie działa jako NT AUTHORITY\SYSTEM — zwykli użytkownicy RDP nie mogą odczytać pamięci procesu.
    Możesz podać dedykowane konto (-ServiceAccount; najlepiej gMSA: DOMENA\vulnbuster$).
  * Katalog data\ (zaszyfrowany sejf, dziennik, kopie) dostaje uprawnienia NTFS tylko dla
    SYSTEM, Administratorów i konta usługi — użytkownicy RDP nie skopiują pliku do ataku offline.
  * Na pulpicie publicznym tworzony jest skrót "VulnBuster" (http://127.0.0.1:<port>).

  Uruchom w PowerShell "Jako administrator" z folderu paczki:
     powershell -ExecutionPolicy Bypass -File .\install-task.ps1
#>
[CmdletBinding()]
param(
    [int]$Port = 8443,
    [string]$BindAddress = "127.0.0.1",
    [string]$ServiceAccount = "",          # puste = SYSTEM; gMSA kończy się na '$'
    [string]$CertFile = "",
    [string]$KeyFile = "",
    [switch]$NoShortcut
)
$ErrorActionPreference = "Stop"
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Uruchom PowerShell jako administrator."
}
$Base = $PSScriptRoot
$Py   = Join-Path $Base "python\python.exe"
$Run  = Join-Path $Base "app\run.py"
$Data = Join-Path $Base "data"
$Logs = Join-Path $Base "logs"
if (-not (Test-Path $Py)) { throw "Nie znaleziono $Py — uruchom skrypt z folderu paczki portable." }
New-Item -ItemType Directory -Force $Data, $Logs | Out-Null

# ---- uprawnienia NTFS do danych i logów
$acct = if ($ServiceAccount) { $ServiceAccount } else { "NT AUTHORITY\SYSTEM" }
foreach ($d in $Data, $Logs) {
    & icacls $d /inheritance:r | Out-Null
    & icacls $d /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null   # SYSTEM, Administratorzy
    if ($ServiceAccount) { & icacls $d /grant:r "${ServiceAccount}:(OI)(CI)M" | Out-Null }
}
Write-Host "Uprawnienia: $Data i $Logs dostępne tylko dla SYSTEM, Administratorów$(if ($ServiceAccount) { " i $ServiceAccount" })"

# ---- zadanie
$taskArgs = "`"$Run`" --host $BindAddress --port $Port --data `"$Data\vulnbuster.json.enc`" --log `"$Logs\vulnbuster.log`" --quiet"
if ($CertFile) { $taskArgs += " --cert `"$CertFile`" --key `"$KeyFile`"" }
$action   = New-ScheduledTaskAction -Execute $Py -Argument $taskArgs -WorkingDirectory $Base
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
            -MultipleInstances IgnoreNew -StartWhenAvailable
if (-not $ServiceAccount) {
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Limited
} elseif ($ServiceAccount.EndsWith('$')) {
    $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType Password -RunLevel Limited   # gMSA
} else {
    $principal = $null
}
if (Get-ScheduledTask -TaskName "VulnBuster" -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName "VulnBuster" -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName "VulnBuster" -Confirm:$false
}
if ($principal) {
    Register-ScheduledTask -TaskName "VulnBuster" -Action $action -Trigger $trigger -Settings $settings -Principal $principal `
        -Description "VulnBuster — zarządzanie podatnościami" | Out-Null
} else {
    $cred = Get-Credential -UserName $ServiceAccount -Message "Hasło konta usługi VulnBuster"
    Register-ScheduledTask -TaskName "VulnBuster" -Action $action -Trigger $trigger -Settings $settings `
        -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Limited `
        -Description "VulnBuster — zarządzanie podatnościami" | Out-Null
}
Start-ScheduledTask -TaskName "VulnBuster"
Start-Sleep -Seconds 3

# ---- skrót na pulpicie wszystkich użytkowników
$url = if ($CertFile) { "https://${BindAddress}:$Port/" } else { "http://${BindAddress}:$Port/" }
if ($BindAddress -eq "0.0.0.0") { $url = $url -replace "0\.0\.0\.0", "127.0.0.1" }
if (-not $NoShortcut) {
    $lnk = Join-Path ([Environment]::GetFolderPath("CommonDesktopDirectory")) "VulnBuster.url"
    $ico = Join-Path $Base "app\vulnbuster\static\logo.ico"
    "[InternetShortcut]`r`nURL=$url`r`nIconFile=$ico`r`nIconIndex=0`r`n" | Set-Content -Path $lnk -Encoding ASCII
    Write-Host "Skrót: $lnk"
}
try {
    $r = Invoke-WebRequest -Uri ($url + "api/status") -UseBasicParsing -TimeoutSec 10
    Write-Host "VulnBuster działa: $url  ($($r.Content))" -ForegroundColor Green
} catch {
    Write-Warning "Zadanie zarejestrowane, ale serwer jeszcze nie odpowiada. Sprawdź $Logs\vulnbuster.log"
}
