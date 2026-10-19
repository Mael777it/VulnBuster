# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Marcin Lewandowski <marcin.lewandowski.x@gmail.com>
<#
.SYNOPSIS
  Buduje przenośną paczkę VulnBuster z wbudowanym Pythonem (Windows x64).

.DESCRIPTION
  Uruchom na dowolnym komputerze z Windows i dostępem do Internetu. Na serwerze docelowym
  (lab) NIC nie trzeba instalować — kopiujesz tylko gotowy folder / zip.

  Skrypt:
    1. pobiera oficjalny "embeddable package" Pythona z python.org i weryfikuje, że się uruchamia,
    2. instaluje do niego pip oraz biblioteki z requirements.txt (cryptography, openpyxl),
    3. kopiuje aplikację i skrypty startowe,
    4. pakuje całość do VulnBuster-portable.zip.

  Tryb offline: przygotuj wcześniej katalog z kołami (wheels) poleceniem
     pip download -r requirements.txt --only-binary=:all: --platform win_amd64 --python-version 3.12 -d wheels
  i podaj go w -WheelDir (get-pip.py i zip Pythona wtedy też podaj lokalnie: -PythonZip, -GetPip).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\portable\build-portable.ps1
.EXAMPLE
  .\portable\build-portable.ps1 -PythonVersion 3.12.10 -OutDir C:\build\VulnBuster
#>
[CmdletBinding()]
param(
    [string]$PythonVersion = "3.12.10",
    [string]$OutDir = "",
    [string]$PythonZip = "",
    [string]$GetPip = "",
    [string]$WheelDir = "",
    [switch]$NoZip
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Root = Split-Path $PSScriptRoot -Parent
if (-not $OutDir) { $OutDir = Join-Path $Root "dist\VulnBuster" }
$Tmp  = Join-Path $env:TEMP ("vulnbuster-build-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force $Tmp | Out-Null

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

if (Test-Path $OutDir) {
    Write-Host "Usuwam poprzednią wersję: $OutDir"
    Remove-Item -Recurse -Force $OutDir
}
$PyDir  = Join-Path $OutDir "python"
$AppDir = Join-Path $OutDir "app"
New-Item -ItemType Directory -Force $PyDir, $AppDir, (Join-Path $OutDir "data"), (Join-Path $OutDir "logs") | Out-Null

# ---------------------------------------------------------------- 1. Python embeddable
Step "Python $PythonVersion (embeddable, x64)"
if (-not $PythonZip) {
    $PythonZip = Join-Path $Tmp "python-embed.zip"
    $url = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
    Write-Host "Pobieram $url"
    Invoke-WebRequest -Uri $url -OutFile $PythonZip -UseBasicParsing
}
Expand-Archive -Path $PythonZip -DestinationPath $PyDir -Force

# włączenie site-packages i ścieżki aplikacji w pliku ._pth
$pth = Get-ChildItem $PyDir -Filter "python*._pth" | Select-Object -First 1
if (-not $pth) { throw "Nie znaleziono pliku ._pth w paczce Pythona" }
$zipName = (Get-ChildItem $PyDir -Filter "python*.zip" | Select-Object -First 1).Name
@(
    $zipName,
    ".",
    "Lib\site-packages",
    "..\app",
    "import site"
) | Set-Content -Path $pth.FullName -Encoding ASCII
$py = Join-Path $PyDir "python.exe"
& $py -c "import sys; print('Python', sys.version)"
if ($LASTEXITCODE -ne 0) { throw "Wbudowany Python się nie uruchamia" }

# ---------------------------------------------------------------- 2. pip + biblioteki
Step "pip i biblioteki (cryptography, openpyxl)"
if (-not $GetPip) {
    $GetPip = Join-Path $Tmp "get-pip.py"
    Invoke-WebRequest -Uri "https://bootstrap.pypa.io/get-pip.py" -OutFile $GetPip -UseBasicParsing
}
$req = Join-Path $Root "requirements.txt"
if ($WheelDir) {
    & $py $GetPip --no-warn-script-location --no-index --find-links $WheelDir
    & $py -m pip install --no-warn-script-location --no-index --find-links $WheelDir -r $req
} else {
    & $py $GetPip --no-warn-script-location
    & $py -m pip install --no-warn-script-location --only-binary=:all: -r $req
}
if ($LASTEXITCODE -ne 0) { throw "Instalacja bibliotek nie powiodła się" }
& $py -c "import cryptography, openpyxl; from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('cryptography', cryptography.__version__, '| openpyxl', openpyxl.__version__)"
if ($LASTEXITCODE -ne 0) { throw "Biblioteki nie ładują się w wbudowanym Pythonie" }

# ---------------------------------------------------------------- 3. aplikacja
Step "Kopiowanie aplikacji"
Copy-Item (Join-Path $Root "run.py") $AppDir
Copy-Item (Join-Path $Root "requirements.txt") $AppDir
Copy-Item -Recurse (Join-Path $Root "vulnbuster") $AppDir
if (Test-Path (Join-Path $Root "examples")) { Copy-Item -Recurse (Join-Path $Root "examples") $OutDir }
Copy-Item (Join-Path $Root "README.md") $OutDir
Copy-Item (Join-Path $Root "LICENSE") $OutDir
Copy-Item (Join-Path $Root "LICENSE") $AppDir
Get-ChildItem -Recurse -Directory $AppDir -Filter "__pycache__" | Remove-Item -Recurse -Force
foreach ($f in "start.bat", "install-task.ps1", "uninstall-task.ps1", "INSTRUKCJA-SERWER.txt") {
    Copy-Item (Join-Path $PSScriptRoot $f) $OutDir
}

# test: aplikacja importuje się i testy jednostkowe przechodzą
Step "Test uruchomienia"
& $py -c "import vulnbuster.server as s; print('VulnBuster OK:', s.APP_NAME)"
if ($LASTEXITCODE -ne 0) { throw "Aplikacja nie importuje się" }
if (Test-Path (Join-Path $Root "tests")) {
    Push-Location $Root
    & $py -m unittest discover -s tests
    $t = $LASTEXITCODE
    Pop-Location
    if ($t -ne 0) { throw "Testy nie przeszły" }
}

# ---------------------------------------------------------------- 4. zip
if (-not $NoZip) {
    Step "Pakowanie"
    $zip = Join-Path (Split-Path $OutDir -Parent) "VulnBuster-portable.zip"
    if (Test-Path $zip) { Remove-Item $zip }
    Compress-Archive -Path $OutDir -DestinationPath $zip
    Write-Host "Gotowe: $zip  ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB)" -ForegroundColor Green
} else {
    Write-Host "Gotowe: $OutDir" -ForegroundColor Green
}
Remove-Item -Recurse -Force $Tmp
Write-Host "Na serwerze: rozpakuj, uruchom PowerShell jako administrator i wykonaj .\install-task.ps1"
