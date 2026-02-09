# Contributing to LLM Plugin Tester

Thank you for your interest in improving LLM Plugin Abuse Tester!

## How to Contribute

### Reporting Bugs
- **Check existing issues** before creating new ones
- **Include:**
  - Steps to reproduce
  - Expected vs actual behavior
  - Environment (OS, Python version)
  - Example plugin manifest (if applicable)

### Suggesting Enhancements
- **New attack vectors:** Describe the vulnerability type
- **Detection methods:** Explain how to identify it
- **PoC:** Provide proof of concept if possible

### Pull Requests

#### Setup Development Environment
```bash
git clone https://github.com/yourusername/llm-plugin-tester.git
cd llm-plugin-tester
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

#### Before Submitting
1. **Run tests:**
   ```bash
   pytest tests/ -v --cov
   ```

2. **Lint code:**
   ```bash
   ruff check src/
   black src/ --check
   mypy src/
   ```

3. **Add tests** for new features

4. **Update docs** if adding CLI commands or detectors

#### PR Guidelines
- **Clear title:** `[Module] Brief description`
- **Link issue:** `Fixes #123`
- **Small PRs:** Focus on single feature/fix
- **Document changes:** Update README/docs as needed

## Code Style

- **Black** for formatting (line length: 100)
- **Type hints** for all functions
- **Docstrings** for modules, classes, public methods
- **Descriptive names:** `detect_ssrf_vulnerability()` not `check()`

## Priority Areas

### High Impact Contributions
1. **New detectors** (Module 2: Proxy, Module 3: Fuzzer)
2. **Promptfoo/Garak integration** for adversarial testing
3. **MITRE ATT&CK automation** in reports
4. **CI/CD integration** examples

### Documentation
- Real-world exploitation walkthroughs
- Video tutorials
- Additional example vulnerable plugins

## Questions?

Open a discussion or issue. We're here to help!
