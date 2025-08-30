# PyPI Release Checklist

## Pre-Release
- [ ] Update version in `setup.py`
- [ ] Update README.md with latest features
- [ ] Test all functionality locally
- [ ] Run tests: `python -m pytest`
- [ ] Clean previous builds: `rm -rf dist/ build/ *.egg-info/`
- [ ] Build package: `python -m build`

## TestPyPI Upload
- [ ] Upload to TestPyPI: `python -m twine upload --repository testpypi dist/*`
- [ ] Test installation from TestPyPI
- [ ] Verify CLI works: `forensiq-cli --help`
- [ ] Test core functionality

## PyPI Upload (Production)
- [ ] Upload to PyPI: `python -m twine upload dist/*`
- [ ] Verify installation: `pip install forensiq-aiagent`
- [ ] Test in clean environment
- [ ] Update GitHub release tags
- [ ] Update documentation

## Post-Release
- [ ] Monitor for issues
- [ ] Update project documentation
- [ ] Announce release (if applicable)
