# Builds dist\Glide.exe (single file, no Python needed to run it).
# Usage:  powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

if (-not (Test-Path .build-venv)) { python -m venv .build-venv }
.\.build-venv\Scripts\python -m pip install -q --upgrade pip
.\.build-venv\Scripts\python -m pip install -q pyinstaller pynput cryptography vgamepad

.\.build-venv\Scripts\pyinstaller --noconfirm --clean --onefile --name Glide `
  --hidden-import pynput.keyboard._win32 --hidden-import pynput.mouse._win32 `
  --collect-all vgamepad `
  --icon icons\glide.ico --add-data "icons\*.png;icons" `
  glide.py

Write-Host "`nBuilt: $PSScriptRoot\dist\Glide.exe"
