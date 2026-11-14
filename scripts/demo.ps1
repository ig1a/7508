$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
& '.\.venv\Scripts\python.exe' scripts/demo.py
if ($LASTEXITCODE -ne 0) { throw 'Demo failed. Check the report or terminal message.' }
