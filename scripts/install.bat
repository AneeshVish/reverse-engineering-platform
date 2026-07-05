@echo off
setlocal
cd /d "%~dp0\.."

set PYTHON=python
set VENV=%CD%\.venv

echo ==^> Creating virtual environment
%PYTHON% -m venv %VENV%
call %VENV%\Scripts\activate.bat

echo ==^> Installing RevENG dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install PyQt6-WebEngine

echo @echo off > RevENG.bat
echo cd /d "%CD%" >> RevENG.bat
echo call "%VENV%\Scripts\activate.bat" >> RevENG.bat
echo python main.py %%* >> RevENG.bat

echo.
echo Installation complete.
echo   Run the app:  RevENG.bat
echo   Or:           %VENV%\Scripts\python main.py
echo.
echo Optional power features: pip install -r requirements-optional.txt

endlocal
