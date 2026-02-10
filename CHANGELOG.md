# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Module 3: Adversarial Fuzzer (Promptfoo/Garak integration)
- Live mitmproxy proxy pipeline
- SSRF mutation engine
- MITRE ATT&CK automated mapping
- HTML report generation

## [0.1.1] - 2026-02-10

### Fixed
- **CRITICAL:** GPT Action manifest detection — was checking for non-existent `openapi_url` key, now properly detects via `schema_version` and `api.type`
- **CRITICAL:** MCP file access false positives — `/` in `dangerous_paths` matched every unix path argument, now uses exact-match set
- GPT Action analysis no longer returns early, skipping endpoint analysis on manifests with paths
- Base64 secret regex tightened from 40 to 64 chars to reduce false positives
- Replaced raw `print()` with `loguru` in interceptor for consistent logging
- Removed unused imports (`asyncio`, `Optional`)
- Fixed `yourusername` → `Ak-cybe` in all URLs (pyproject.toml, docs, CONTRIBUTING)

### Added
- **36 new tests** — proxy detectors (13 tests) and payload library (23 tests)
- Full test coverage across all 5 modules (55 tests total)
- GitHub Actions CI pipeline (Python 3.10–3.13, Ubuntu + Windows)
- SECURITY.md with vulnerability disclosure policy
- Issue templates (bug report + feature request)
- Pull request template
- Professional README with badges, architecture diagram, comparison table

### Removed
- Unused dependencies: `jinja2`, `requests` (never imported)

## [0.1.0] - 2026-02-09

### Added
- **Module 1: Reconnaissance Engine**
  - OpenAPI parser for GPT Actions with authentication analysis
  - MCP configuration auditor with file access, CORS, hooks, permission checks
  - Risky parameter detection across 15+ dangerous keywords
  - Broad schema detection (`additionalProperties: true`)

- **Module 2: Interception Proxy**
  - mitmproxy-based traffic interceptor
  - `HallucinationDetector` — flags parameters not in OpenAPI schema
  - `SSRFDetector` — 16 regex patterns for cloud metadata, internal IPs, file protocols
  - `SensitiveDataDetector` — catches API keys, tokens, secrets, AWS credentials

- **Module 4: Validation Oracle**
  - FastAPI listener server for proving exfiltration
  - Markdown image exfiltration detection
  - GET/POST parameter extraction and severity assessment
  - Transparent GIF response for image requests

- **Attack Payload Library**
  - 75+ payloads across 7 categories:
    - Markdown exfiltration (7 templates)
    - SSRF (24 payloads across 6 categories)
    - Hallucinated parameters (20 payloads)
    - Indirect prompt injection (6 prompts)
    - Tool chaining (4 attack chains)
    - LangGrinch / Deserialization RCE (3 payloads)
    - MCP abuse (11 payloads)
  - `generate_oracle_payload()` and `generate_ssrf_test_suite()` helpers

- **CLI Interface**
  - `analyze` command for GPT Actions and MCP servers
  - `oracle start` command for validation listener
  - Rich console output with color-coded severity tables

- **HackerOne Report Templates**
  - SSRF report template (CVSS 9.0)
  - Markdown exfiltration report template (CVSS 7.5)
  - CVSS scoring guide

- **Documentation**
  - Attack vectors guide with 7 exploitation walkthroughs
  - Bug bounty integration playbook with payout estimates
  - Contributing guidelines

### Security
- Detection coverage for OWASP LLM Top 10 categories:
  - LLM01: Prompt Injection
  - LLM02: Insecure Output Handling
  - LLM07: Insecure Plugin Design
  - LLM08: Excessive Agency
