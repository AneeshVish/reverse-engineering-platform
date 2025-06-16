# PowerShell script to fix python-magic/libmagic errors on Windows
# Downloads and places magic1.dll (libmagic) in the project root

$libmagicUrl = "https://github.com/ahupp/python-magic-bin/releases/download/0.4.27/libmagic-0.4.27-win64.zip"
$zipPath = "libmagic-0.4.27-win64.zip"
$extractDir = "libmagic_tmp"

Write-Host "Downloading libmagic DLL for Windows..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $libmagicUrl -OutFile $zipPath

Write-Host "Extracting DLL..." -ForegroundColor Cyan
Expand-Archive $zipPath -DestinationPath $extractDir -Force

# Copy DLL to project root
$srcDll = Join-Path $extractDir "bin\magic1.dll"
$dstDll = Join-Path (Get-Location) "magic1.dll"
Copy-Item $srcDll $dstDll -Force

Write-Host "Cleaning up..." -ForegroundColor Yellow
Remove-Item $zipPath -Force
Remove-Item $extractDir -Recurse -Force

Write-Host "libmagic DLL installed as magic1.dll in project root. python-magic should now work!" -ForegroundColor Green
