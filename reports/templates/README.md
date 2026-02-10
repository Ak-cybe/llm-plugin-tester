# HackerOne Report Templates for LLM Plugin Vulnerabilities

This directory contains ready-to-submit bug bounty report templates for common LLM plugin vulnerabilities detected by this tool.

---

## 📋 Report Templates

### 1. [SSRF via Plugin URL Parameter](./ssrf_report.md)
### 2. [Markdown Image Exfiltration](./markdown_exfil_report.md)
### 3. [Over-Permissions in GPT Action](./over_permissions_report.md)
### 4. [Tool Chaining Without Approval](./tool_chaining_report.md)
### 5. [Hallucinated Parameter Exploitation](./hallucinated_params_report.md)

---

## 🎯 Usage

1. Run `llm-plugin-tester` to identify vulnerabilities
2. Copy the relevant template
3. Fill in the `[PLACEHOLDERS]` with your findings
4. Attach evidence (JSON reports, logs, screenshots)
5. Submit to the appropriate bug bounty program

---

## ⚡ Quick Template Format

All templates follow this structure:

```markdown
**Title:** [Vulnerability Type] in [Component]

**Severity:** [CRITICAL/HIGH/MEDIUM/LOW]

**Summary:** [1-2 sentence description]

**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Proof of Concept:**
[Code/payload/screenshot]

**Impact:**
[What an attacker can achieve]

**Remediation:**
[How to fix it]

**Evidence:**
[Attach files]
```

---

## 📊 CVSS Scoring Guide

| Vulnerability | Base Score | Vector |
|---------------|------------|--------|
| SSRF → AWS creds | 9.0 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |
| Markdown exfil (API key) | 7.5 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N |
| Tool chaining | 8.0 | CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N |
| Over-permissions | 5.3 | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N |
