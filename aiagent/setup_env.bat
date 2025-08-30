@echo off
echo Setting up PyPI upload environment...

REM Copy .env.example to .env and edit it with your actual tokens
if not exist .env (
    copy .env.example .env
    echo Please edit .env file with your actual API tokens
    echo Then run this script again
    pause
    exit /b 1
)

REM Load environment variables from .env file
for /f "usebackq tokens=1,2 delims==" %%i in (".env") do (
    if "%%i"=="TESTPYPI_API_TOKEN" set TESTPYPI_TOKEN=%%j
    if "%%i"=="PYPI_API_TOKEN" set PYPI_TOKEN=%%j
)

echo Environment loaded. You can now upload to PyPI.
echo.
echo Available commands:
echo 1. Upload to TestPyPI: upload_testpypi.bat
echo 2. Upload to PyPI: upload_pypi.bat
echo.
pause
