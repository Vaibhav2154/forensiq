#!/bin/bash
# test_package_installation.sh

echo "Testing ForensIQ AI Agent Package Installation..."

# Create a test virtual environment
python -m venv test_env
source test_env/bin/activate  # On Windows: test_env\Scripts\activate

# Install from TestPyPI
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ forensiq-aiagent

# Test basic functionality
echo "Testing CLI installation..."
forensiq-cli --help

echo "Testing Python import..."
python -c "import aiagent; print('Package imported successfully')"

# Cleanup
deactivate
rm -rf test_env

echo "Package testing complete!"
