@echo off
echo ========================================
echo  Upload to PyPI (Production)
echo ========================================
echo.

REM Check if distribution files exist
if not exist "dist\*.whl" (
    echo No distribution files found. Building package...
    D:/forensiq/server/.venv/Scripts/python.exe -m build
    echo.
)

echo WARNING: This will upload to PRODUCTION PyPI!
echo Make sure you have tested on TestPyPI first.
echo.
set /p confirm="Are you sure you want to continue? (y/N): "
if /i not "%confirm%"=="y" (
    echo Upload cancelled.
    pause
    exit /b 1
)

echo Please ensure you have:
echo 1. Created an account at https://pypi.org/
echo 2. Generated an API token at https://pypi.org/manage/account/token/
echo.

REM Method 1: Using environment variable (recommended)
if defined PYPI_API_TOKEN (
    echo Using API token from environment variable...
    D:/forensiq/server/.venv/Scripts/python.exe -m twine upload dist/* --username __token__ --password %PYPI_API_TOKEN%
    goto :end
)

REM Method 2: Interactive input (will prompt for password)
echo No environment variable found. You will be prompted for your API token.
echo Enter '__token__' as username and your API token as password when prompted.
echo.
D:/forensiq/server/.venv/Scripts/python.exe -m twine upload dist/*

:end
echo.
echo Upload completed! 
echo Install with: pip install forensiq-aiagent
echo.
pause
