@echo off
REM test_package_installation.bat

echo Testing ForensIQ AI Agent Package Installation...

REM Create a test virtual environment
python -m venv test_env
call test_env\Scripts\activate

REM Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ forensiq-aiagent

REM Test basic functionality
echo Testing CLI installation...
forensiq-cli --help

echo Testing Python import...
python -c "import aiagent; print('Package imported successfully')"

REM Cleanup
call deactivate
rmdir /s /q test_env

echo Package testing complete!
pause
