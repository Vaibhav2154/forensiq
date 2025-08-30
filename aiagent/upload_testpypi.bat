@echo off
echo ========================================
echo  Upload to TestPyPI
echo ========================================
echo.

REM Check if distribution files exist
if not exist "dist\*.whl" (
    echo No distribution files found. Building package...
    D:/forensiq/server/.venv/Scripts/python.exe -m build
    echo.
)

echo Please ensure you have:
echo 1. Created an account at https://test.pypi.org/
echo 2. Generated an API token at https://test.pypi.org/manage/account/token/
echo.

REM Method 1: Using environment variable (recommended)
if defined TESTPYPI_API_TOKEN (
    echo Using API token from environment variable...
    D:/forensiq/server/.venv/Scripts/python.exe -m twine upload --repository testpypi dist/* --username __token__ --password %TESTPYPI_API_TOKEN%
    goto :end
)

REM Method 2: Interactive input (will prompt for password)
echo No environment variable found. You will be prompted for your API token.
echo Enter '__token__' as username and your API token as password when prompted.
echo.
D:/forensiq/server/.venv/Scripts/python.exe -m twine upload --repository testpypi dist/*

:end
echo.
echo Upload completed! 
echo Test installation with:
echo pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ forensiq-aiagent
echo.
pause
