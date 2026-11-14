$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    throw 'Run scripts/setup.ps1 first.'
}
# One worker is required for the in-memory session store.
& '.\.venv\Scripts\python.exe' -m uvicorn main:app --host 127.0.0.1 --port 8000
if ($LASTEXITCODE -ne 0) { throw 'Backend stopped with an error.' }
