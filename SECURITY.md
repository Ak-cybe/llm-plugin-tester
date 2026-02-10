# Security Policy

## Supported Versions

| Version | Supported          |
|:--------|:------------------:|
| 0.1.x   | ✅ Active          |
| < 0.1   | ❌ Not supported   |

## Reporting a Vulnerability

We take security seriously — especially for a security testing tool.

### 🔒 Private Disclosure

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead:

1. **Email:** Send details to the repository maintainer via GitHub private advisory
2. **GitHub Security Advisory:** Use the [Security tab](https://github.com/Ak-cybe/llm-plugin-tester/security/advisories/new) to report privately

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Action | Expected Time |
|:---|:---|
| Acknowledgment | 48 hours |
| Initial assessment | 5 business days |
| Fix release | 14 business days |
| Public disclosure | 30 days after fix |

### Scope

**In scope:**
- Code execution vulnerabilities in the tool itself
- Credential exposure in logs or reports
- Dependencies with known CVEs
- Bypasses in detection logic

**Out of scope:**
- Vulnerabilities in example/test plugins (they're intentionally vulnerable)
- Feature requests
- Issues in third-party dependencies (report upstream)

## Security Design Principles

This tool handles sensitive data (API keys, vulnerability details, network traffic). Our commitments:

1. **No telemetry** — Zero data sent anywhere
2. **Local-first** — All analysis runs on your machine
3. **No credential storage** — We never store target API keys
4. **Minimal permissions** — Tool requests only what it needs
5. **Audit trail** — All findings logged with timestamps

## Dependency Security

We monitor dependencies via:
- Dependabot alerts (enabled)
- Regular `pip-audit` checks
- Pinned dependency versions in `pyproject.toml`
