@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0\.."

set PYTHON=python
set VENV=.venv-build

echo ==^> Creating build venv at %VENV%
%PYTHON% -m venv %VENV%
call %VENV%\Scripts\activate.bat

echo ==^> Installing dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-packaging.txt

echo ==^> Building with PyInstaller
pyinstaller --noconfirm packaging\reveng.spec

echo.
echo Build complete: dist\RevENG\RevENG.exe
echo Launch: dist\RevENG\RevENG.exe
echo.
echo Optional: zip dist\RevENG as RevENG-windows.zip for distribution

endlocal
