@echo off
echo ========================================
echo  PyPI Configuration Setup
echo ========================================
echo.

echo This script will help you set up your PyPI configuration securely.
echo.

echo Step 1: Get your API tokens
echo.
echo For TestPyPI:
echo 1. Go to https://test.pypi.org/account/register/ (if you don't have an account)
echo 2. Go to https://test.pypi.org/manage/account/token/
echo 3. Create a new API token
echo 4. Copy the token (it starts with 'pypi-')
echo.
echo For PyPI:
echo 1. Go to https://pypi.org/account/register/ (if you don't have an account)
echo 2. Go to https://pypi.org/manage/account/token/
echo 3. Create a new API token
echo 4. Copy the token (it starts with 'pypi-')
echo.

echo Step 2: Choose configuration method
echo.
echo 1. Environment Variables (.env file) - Recommended
echo 2. PyPI Configuration File (.pypirc)
echo 3. Manual input each time
echo.

set /p choice="Enter your choice (1-3): "

if "%choice%"=="1" goto :env_setup
if "%choice%"=="2" goto :pypirc_setup
if "%choice%"=="3" goto :manual_setup

echo Invalid choice. Exiting.
pause
exit /b 1

:env_setup
echo.
echo Setting up .env file...
if not exist .env copy .env.example .env
echo Please edit the .env file and replace the placeholder tokens with your actual tokens.
echo Then use upload_testpypi.bat or upload_pypi.bat
start notepad .env
goto :end

:pypirc_setup
echo.
echo Setting up .pypirc file...
echo Please edit the .pypirc file and replace the placeholder tokens with your actual tokens.
echo The file will be created in your home directory: %USERPROFILE%\.pypirc
copy .pypirc "%USERPROFILE%\.pypirc"
start notepad "%USERPROFILE%\.pypirc"
goto :end

:manual_setup
echo.
echo Manual setup selected.
echo You will be prompted for tokens each time you upload.
echo Use upload_testpypi.bat or upload_pypi.bat for uploads.
goto :end

:end
echo.
echo Configuration setup complete!
echo Run upload_testpypi.bat to test your package upload.
echo.
pause
