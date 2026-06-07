$envFile = Join-Path $PSScriptRoot "backend\.env.local"
Get-Content $envFile | ForEach-Object {
    if ($_ -and -not $_.StartsWith("#")) {
        $name, $value = $_ -split "=", 2
        [System.Environment]::SetEnvironmentVariable($name, $value, "Process")
    }
}

$python = "C:\Program Files\MySQL\MySQL Workbench 8.0\python.exe"
$env:PYTHONHOME = "C:\Program Files\MySQL\MySQL Workbench 8.0\python"
$backendPath = Join-Path $PSScriptRoot "backend"
$sitePackages = Join-Path $backendPath ".venv\Lib\site-packages"
$env:PYTHONPATH = "$backendPath;$sitePackages"

Set-Location $backendPath
& $python -m app.db.seed
$serverScript = @"
import sys
sys.path.insert(0, r"$backendPath")
import uvicorn
uvicorn.run("app.main:app", host="127.0.0.1", port=8000)
"@
$serverScript | & $python -
