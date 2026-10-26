param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8765,
    [switch]$Reload,
    [switch]$NoBrowser,
    [switch]$BuildCss,
    [switch]$RunTests
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

if (-not (Test-Path ".env") -and (Test-Path ".env.example")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[Launcher] File .env berhasil dibuat dari .env.example" -ForegroundColor Cyan
}

if ($RunTests) {
    Write-Host "[Launcher] Menjalankan pytest..." -ForegroundColor Yellow
    python -m pytest -v
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$argsList = @("launch.py", "--host", $HostAddress, "--port", "$Port")
if ($Reload) { $argsList += "--reload" }
if ($NoBrowser) { $argsList += "--no-browser" }
if ($BuildCss) { $argsList += "--build-css" }

python @argsList
