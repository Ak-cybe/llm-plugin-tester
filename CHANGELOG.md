# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-09

### Added
- **Module 1: Reconnaissance Engine**
  - OpenAPI parser for GPT Actions
  - MCP configuration auditor
  - Risky parameter detection
  - Authentication analyzer
  - CORS and hook configuration checks
  
- **Module 4: Validation Oracle**
  - FastAPI-based listener server
  - Markdown image exfiltration detection
  - Query parameter extraction and logging
  - Severity assessment for exfiltration attempts
  
- **CLI Interface**
  - `analyze` command for GPT Actions and MCP servers
  - `oracle` command to start validation listener
  - Rich console output with color-coded findings
  
- **Testing Framework**
  - Pytest test suites for all modules
  - Example vulnerable plugins for testing
  - FastAPI test client for Oracle testing
  
- **Documentation**
  - Comprehensive README with quick start
  - Attack vectors guide with exploitation examples
  - Bug bounty integration guide
  - Contributing guidelines

### Security
- Implemented detection for:
  - Over-permissions in plugins
  - SSRF vulnerabilities
  - Authentication weaknesses
  - Data exfiltration paths
  - CORS misconfigurations
  - Dangerous file system access

## [Unreleased]

### Planned
- Module 2: Interception Proxy (mitmproxy integration)
- Module 3: Adversarial Fuzzer (Promptfoo/Garak)
- Hallucinated parameter detection
- Tool chaining validator
- MITRE ATT&CK automated mapping
- HTML report generation
