$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Push-Location $Root
try {
    python -m PyInstaller --noconfirm --clean --onedir --name ai-redteam --hidden-import anthropic main.py
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host "Built dist\ai-redteam\ai-redteam.exe. Run it from the project directory."
}
finally {
    Pop-Location
}
