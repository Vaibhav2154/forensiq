# PyPI Upload Quick Start Guide

## 🚀 Quick Start (3 Steps)

### Step 1: Get API Tokens
1. **TestPyPI**: Go to https://test.pypi.org/manage/account/token/
2. **PyPI**: Go to https://pypi.org/manage/account/token/
3. Create tokens and copy them (they start with `pypi-`)

### Step 2: Configure Authentication
Run the setup script:
```batch
setup_pypi_config.bat
```

Choose your preferred method:
- **Option 1**: Environment variables (recommended)
- **Option 2**: .pypirc file
- **Option 3**: Manual input each time

### Step 3: Upload Your Package

**Test first** (recommended):
```batch
upload_testpypi.bat
```

**Production upload**:
```batch
upload_pypi.bat
```

## 📋 What Each Method Does

### Environment Variables (.env)
- Create `.env` file with your tokens
- Tokens are loaded automatically
- Most secure for development

### .pypirc File
- Standard PyPI configuration
- Stored in your home directory
- Works with all twine commands

### Manual Input
- Prompted for tokens each time
- No tokens stored on disk
- Most secure but inconvenient

## 🔒 Security Tips

1. **Never commit** `.env` or `.pypirc` files to git
2. **Use scoped tokens** (project-specific) when possible
3. **Regenerate tokens** if compromised
4. **Test on TestPyPI first** before production

## 🧪 Testing Your Package

After uploading to TestPyPI:
```batch
test_package_installation.bat
```

Or manually:
```batch
pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ forensiq-aiagent
forensiq-cli --help
```

## 🐛 Troubleshooting

**"Invalid credentials"**
- Check token is correct and starts with `pypi-`
- Username should be `__token__`

**"Package already exists"**
- Update version in `setup.py`
- Rebuild: `python -m build`

**"No distribution files"**
- Run build first: `python -m build`
- Check `dist/` folder exists

## 📞 Need Help?

Run any of these for guided setup:
- `setup_pypi_config.bat` - Configure authentication
- `upload_testpypi.bat` - Upload to test repository
- `upload_pypi.bat` - Upload to production
