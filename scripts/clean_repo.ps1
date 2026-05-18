# Remove local build artifacts before git push
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\clean_repo.ps1
$ErrorActionPreference = "SilentlyContinue"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

@(
    ".venv", "ffuf_intel\.venv", "ffuf_intel.egg-info",
    "dist", "build", ".pytest_cache", ".mypy_cache", ".ruff_cache"
) | ForEach-Object {
    $p = Join-Path $root $_
    if (Test-Path $p) { Remove-Item -Recurse -Force $p; Write-Host "Removed $p" }
}

Get-ChildItem -Path $root -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item -Recurse -Force $_.FullName }
Get-ChildItem -Path $root -Recurse -Filter "*.pyc" -ErrorAction SilentlyContinue |
    ForEach-Object { Remove-Item -Force $_.FullName }
if (Test-Path "$root\tools\ffuf.exe") { Remove-Item -Force "$root\tools\ffuf.exe" }
Write-Host "Repository cleaned: $root"
