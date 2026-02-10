# v0.1.0 Release Checklist

## Pre-Release Verification

### Code Quality
- [x] All tests passing (`pytest tests/ -v`)
- [x] Type hints present on all public functions
- [x] Docstrings on all modules, classes, and public methods
- [x] No TODO comments in production code
- [x] Consistent code style (black, ruff)

### Security
- [x] No hardcoded credentials or API keys
- [x] .gitignore includes sensitive files
- [x] .env.example provided (not .env)
- [x] Dependencies pinned to minimum versions
- [x] No known vulnerabilities in dependencies

### Documentation
- [x] README.md with:
  - [x] Problem statement
  - [x] Threat model
  - [x] Installation instructions
  - [x] Usage examples
  - [x] Architecture diagram
  - [x] License
- [x] CONTRIBUTING.md
- [x] CHANGELOG.md
- [x] Attack vectors documentation
- [x] Bug bounty integration guide

### Package Configuration
- [x] pyproject.toml complete
- [x] Version set to 0.1.0
- [x] Author and email configured
- [x] License specified (MIT)
- [x] Keywords and classifiers set
- [x] Entry point defined (`llm-plugin-tester`)
- [x] Optional dependencies configured

### Examples
- [x] Example vulnerable GPT Action
- [x] Example vulnerable MCP server
- [ ] Example attack payloads (ready-to-use)
- [ ] Example report output

### Tests
- [x] test_openapi_parser.py
- [x] test_mcp_auditor.py
- [x] test_oracle.py
- [ ] test_proxy.py (when Module 2 complete)
- [ ] test_payloads.py

---

## Release Steps

### 1. Final Verification
```bash
# Clean install test
pip uninstall llm-plugin-tester -y
pip install -e .

# Run tests
pytest tests/ -v --cov

# Verify CLI
python -m llm_plugin_tester.cli --help
```

### 2. Update Version
- [x] pyproject.toml: version = "0.1.0"
- [x] src/llm_plugin_tester/__init__.py: __version__ = "0.1.0"
- [x] CHANGELOG.md: Add release date

### 3. Git Tag
```bash
git tag -a v0.1.0 -m "Initial release - Recon Engine + Validation Oracle"
git push origin v0.1.0
```

### 4. GitHub Release
- [ ] Create release from tag v0.1.0
- [ ] Title: "v0.1.0 - Initial Release"
- [ ] Copy CHANGELOG entry to description
- [ ] Mark as "Pre-release" (alpha)

### 5. PyPI (Optional)
```bash
# Build
python -m build

# Upload to TestPyPI first
python -m twine upload --repository testpypi dist/*

# Then PyPI
python -m twine upload dist/*
```

---

## Post-Release

### Announcement
- [ ] Tweet/Post about release
- [ ] Submit to relevant subreddits (r/netsec, r/AIsecurity)
- [ ] Share in security Discord servers
- [ ] Post on LinkedIn

### Monitoring
- [ ] Watch for GitHub issues
- [ ] Respond to bug reports within 48h
- [ ] Track fork/star growth

### Next Version Planning
- [ ] Create v0.2.0 milestone
- [ ] Add issues for planned features:
  - [ ] mitmproxy integration
  - [ ] SSRF mutation engine
  - [ ] Promptfoo integration
  - [ ] HTML reports

---

## Known Limitations (Document in README)

1. **Static Analysis Only** (v0.1)
   - No runtime traffic interception yet
   - Planned for v0.2

2. **No Web UI**
   - CLI only
   - Planned for v1.0

3. **Limited LangChain Support**
   - GPT Actions and MCP only
   - LangChain tools planned for v0.3

---

## License Compliance

- [x] MIT license file present
- [x] All dependencies compatible with MIT
- [x] No copyleft license contamination
- [x] Attribution in README if required

---

## Security Disclosure

If vulnerabilities are found in this tool:
- Email: [your-email]
- Response time: 48 hours
- Disclosure timeline: 90 days

---

✅ **Ready for Release** when all items checked!
