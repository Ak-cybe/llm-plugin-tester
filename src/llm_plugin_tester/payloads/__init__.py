"""Attack Payloads Module."""

from llm_plugin_tester.payloads.attack_payloads import (
    MARKDOWN_EXFIL_PAYLOADS,
    SSRF_PAYLOADS,
    HALLUCINATION_PAYLOADS,
    INDIRECT_INJECTION_PAYLOADS,
    TOOL_CHAINING_PAYLOADS,
    LANGGRINCH_PAYLOADS,
    MCP_ABUSE_PAYLOADS,
    generate_oracle_payload,
    generate_ssrf_test_suite,
)

__all__ = [
    "MARKDOWN_EXFIL_PAYLOADS",
    "SSRF_PAYLOADS",
    "HALLUCINATION_PAYLOADS",
    "INDIRECT_INJECTION_PAYLOADS",
    "TOOL_CHAINING_PAYLOADS",
    "LANGGRINCH_PAYLOADS",
    "MCP_ABUSE_PAYLOADS",
    "generate_oracle_payload",
    "generate_ssrf_test_suite",
]
