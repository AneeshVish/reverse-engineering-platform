# PowerShell script to install all advanced reverse engineering tools and Python libraries
# Run this script as Administrator for full effect

Write-Host "Installing Python packages..." -ForegroundColor Cyan
$python = "python"
if (!(Get-Command $python -ErrorAction SilentlyContinue)) {
    $python = "python3"
}
$pkgs = @(
    "frida-tools",
    "frida",
    "qiling",
    "angr",
    "capstone",
    "keystone-engine",
    "lief",
    "pefile",
    "pycryptodome",
    "pydbg",
    "r2pipe",
    "unicorn",
    "pyinstaller-extractor",
    "python-magic"
)
foreach ($pkg in $pkgs) {
    Write-Host "Installing $pkg..." -ForegroundColor Yellow
    & $python -m pip install --upgrade $pkg
}

Write-Host "Creating tools directory..." -ForegroundColor Cyan
$toolsDir = "tools"
if (!(Test-Path $toolsDir)) { New-Item -ItemType Directory -Path $toolsDir }

function Download-Tool($url, $outPath) {
    Write-Host "Downloading $url..." -ForegroundColor Green
    Invoke-WebRequest -Uri $url -OutFile $outPath
}

# Download Detect It Easy (DIE)
$dieUrl = "https://github.com/horsicq/Detect-It-Easy/releases/download/3.10/die_win64_portable_3.10.zip"
$dieZip = "$toolsDir\die.zip"
Download-Tool $dieUrl $dieZip
Expand-Archive $dieZip -DestinationPath $toolsDir -Force

# Download UPX
$upxUrl = "https://github.com/upx/upx/releases/download/v5.0.1/upx-5.0.1-win64.zip"
$upxZip = "$toolsDir\upx.zip"
Download-Tool $upxUrl $upxZip
Expand-Archive $upxZip -DestinationPath $toolsDir -Force

# Download Radare2
$r2Url = "https://github.com/radareorg/radare2/releases/download/5.9.0/radare2-w32-5.9.0.zip"
$r2Zip = "$toolsDir\r2.zip"
Download-Tool $r2Url $r2Zip
Expand-Archive $r2Zip -DestinationPath $toolsDir -Force

# Download RetDec
$retdecUrl = "https://github.com/avast/retdec/releases/download/v5.0/retdec-v5.0-win64.zip"
$retdecZip = "$toolsDir\retdec.zip"
Download-Tool $retdecUrl $retdecZip
Expand-Archive $retdecZip -DestinationPath $toolsDir -Force

# Download Ghidra
$ghidraUrl = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.4_build/ghidra_11.0.4_PUBLIC_20240521.zip"
$ghidraZip = "$toolsDir\ghidra.zip"
Download-Tool $ghidraUrl $ghidraZip
Expand-Archive $ghidraZip -DestinationPath $toolsDir -Force

Write-Host "Download x64dbg manually from https://x64dbg.com/#start if needed."
Write-Host "Download PEiD, Scylla, ImpRec, QEMU, VirtualBox, UnpacMe as needed."
Write-Host "Add $toolsDir to your PATH for easy CLI access."
Write-Host "All core open-source RE tools are now installed! Enjoy your research platform!" -ForegroundColor Cyan
