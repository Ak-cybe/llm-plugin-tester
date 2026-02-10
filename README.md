<div align="center">

# 🕵️ LLM Plugin Abuse Tester

[![Build Status](https://img.shields.io/github/actions/workflow/status/Ak-cybe/llm-plugin-tester/ci.yml?style=flat-square&logo=github)](https://github.com/Ak-cybe/llm-plugin-tester/actions)
[![PyPI version](https://img.shields.io/pypi/v/llm-plugin-tester?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/llm-plugin-tester/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square)](https://github.com/psf/black)

**Automated Security Auditing for the Agentic AI Era**

Because trusting third-party plugins blindly equals a data breach.

[Problem](#-the-problem) • [Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Attack Vectors](#-attack-vectors) • [Roadmap](#-roadmap)

---
</div>

## 💡 The Problem

When you authorize an LLM plugin (GPT Action, MCP Server, or Agent Tool), you grant a **probabilistic model** the authority to execute **privileged actions** inside your security perimeter.

> **"One vulnerable plugin is enough to compromise your entire session."**

LLM providers do NOT audit how third-party plugins:
*   Validate model-generated inputs (hallucinations)
*   Prevent Server-Side Request Forgery (SSRF)
*   Protect against Indirect Prompt Injection
*   Detect Data Exfiltration attempts

**This tool detects and proves those failures automatically.**

---

## ✨ Features

### 🔍 Reconnaissance Engine (Static Analysis)
Audit configurations without sending a single packet.
- **GPT Actions:** Parse `ai-plugin.json` and OpenAPI specs for risky endpoints (`/exec`, `/sql`).
- **MCP Servers:** Audit `mcp-config.json` for excessive file access (`/`, `~`) and dangerous permissions.
- **Reporting:** Generates detailed JSON reports with severity ratings (CRITICAL / HIGH / MEDIUM).

### 🧪 Validation Oracle (Active Testing)
The "smoking gun" proof for bug bounty reports.
- **Zero-Click Exfiltration:** Detects markdown image rendering attacks.
- **SSRF Confirmation:** Catches cloud metadata access attempts.
- **Secret Extraction:** Logs query parameters containing keys/tokens.
- **Evidence Logging:** Timestamped proof for triagers.

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Ak-cybe/llm-plugin-tester.git
cd llm-plugin-tester

# Install in editable mode
pip install -e .

# Verify installation
llm-plugin-tester --help
```

---

## 🎬 Usage

### 1. Analyze a GPT Action (Static)
Identify vulnerabilities in an OpenAPI specification.

```bash
llm-plugin-tester analyze \
  --type gpt-action \
  --manifest ./examples/vulnerable-plugin/ai-plugin.json \
  --output-dir ./reports
```

**Output:**
```text
🚨 Found 3 security issues:
  CRITICAL: 1 | HIGH: 1 | MEDIUM: 1

┌──────────┬─────────────────┬──────────────┬─────────────────────────────────┐
│ Severity │ Endpoint        │ Risky Params │ Reason                          │
├──────────┼─────────────────┼──────────────┼─────────────────────────────────┤
│ CRITICAL │ POST /execute   │ command      │ Accepts arbitrary command exec  │
│ HIGH     │ GET /fetch      │ url          │ Potential SSRF vector           │
└──────────┴─────────────────┴──────────────┴─────────────────────────────────┘
```

### 2. Audit an MCP Server Configuration
Check your local Claude Desktop or VS Code MCP settings.

```bash
llm-plugin-tester analyze \
  --type mcp \
  --config ~/.config/claude/mcp-config.json
```

**Detects:**
- Root filesystem access (`/` or `C:\`)
- Broad network permissions
- Dangerous capabilities (shell access)

### 3. Start the Validation Oracle
Run a listener to catch exfiltration attempts during testing.

```bash
# Start the listener on port 8080
llm-plugin-tester oracle start --port 8080
```

---

## 🛡️ Supported Attack Vectors

| Vector | Description | Status |
| :--- | :--- | :--- |
| **Over-Permissions** | Plugin requests more scopes than used | ✅ Supported |
| **SSRF** | Access internal metadata (AWS/GCP/K8s) | ✅ Supported |
| **Markdown Exfil** | Zero-click data theft via image rendering | ✅ Supported |
| **Hallucinations** | Model invents `admin=true` parameters | 🚧 Roadmap |
| **Tool Chaining** | Multi-step attacks (Read DB -> Email) | 🚧 Roadmap |
| **Prompt Injection** | Indirect injection via RAG documents | 🚧 Roadmap |

See [docs/ATTACK_VECTORS.md](docs/ATTACK_VECTORS.md) for detailed exploitation guides.

---

## 💰 Bug Bounty Guide

This tool is **bug-bounty ready**. We include templates and payloads specifically designed for HackerOne and Bugcrowd reports.

*   [**Bug Bounty Guide**](docs/BUG_BOUNTY_GUIDE.md): Workflow, pricing estimates, and target lists.
*   [**Attack Payloads**](src/llm_plugin_tester/payloads/attack_payloads.py): Copy-paste payloads for SSRF, XSS, and Injection.
*   [**Report Templates**](reports/templates/): Pre-formatted Markdown reports for submission.

---

## 🤝 Contributing

We welcome contributions from the security community!

1.  Fork the repo
2.  Create your feature branch (`git checkout -b feature/amazing-feature`)
3.  Commit your changes (`git commit -m 'feat: Add amazing feature'`)
4.  Push to the branch (`git push origin feature/amazing-feature`)
5.  Open a Pull Request

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup.

---

## ⚖️ Legal & Disclaimer

**Usage of this tool for attacking targets without prior mutual consent is illegal.**

LLM Plugin Tester is created for:
*   Security researchers auditing their own systems.
*   Developers securing their AI integrations.
*   Authorized bug bounty engagements.

The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

<div align="center">

**[Report Bug](https://github.com/Ak-cybe/llm-plugin-tester/issues)** • **[Request Feature](https://github.com/Ak-cybe/llm-plugin-tester/issues)**

Made with ❤️ by [Ak-cybe](https://github.com/Ak-cybe)

</div>
