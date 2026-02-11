# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-02-08

### Added
- **Recon Module** — OpenAPI spec parser with risky parameter detection, broad schema analysis, and GPT Action manifest authentication checks
- **Recon Module** — MCP Server auditor detecting excessive file access, CORS wildcards, dangerous permissions, and enabled hooks
- **Proxy Module** — `mitmproxy` integration with real-time detection of hallucinated parameters, SSRF attempts, and sensitive data leaks
- **Payloads Module** — 75+ attack templates across 7 categories: SSRF, markdown exfiltration, hallucinated parameters, prompt injection, tool chaining, LangGrinch RCE, and MCP abuse
- **Oracle Module** — FastAPI validation listener for catching data exfiltration attempts with severity assessment and structured logging
- **Report Templates** — HackerOne-ready templates for SSRF and markdown exfiltration with CVSS scoring guides
- **CLI** — Typer-based interface with `analyze` and `oracle` commands, Rich table output
- **Documentation** — Attack vectors guide, bug bounty integration guide, contributing guidelines
- **Examples** — Vulnerable GPT Action (OpenAPI + ai-plugin.json) and MCP Server configurations for testing
- **Tests** — 55 tests covering all 5 modules with full pass rate

### Fixed
- GPT Action manifest detection logic (was checking non-existent `openapi_url` key)
- MCP file access check false positives (`/` substring match replaced with exact-value match)
- Base64 secret regex tightened from 40 to 64 chars to reduce false positives
- Removed unused dependencies (`jinja2`, `requests`) and dead imports (`asyncio`, `Optional`)
- Project URLs updated from placeholder to actual repository

[0.1.0]: https://github.com/Ak-cybe/llm-plugin-tester/releases/tag/v0.1.0
