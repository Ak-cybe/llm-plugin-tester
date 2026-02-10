"""Tests for Attack Payloads Module."""

import pytest

from llm_plugin_tester.payloads.attack_payloads import (
    HALLUCINATION_PAYLOADS,
    INDIRECT_INJECTION_PAYLOADS,
    LANGGRINCH_PAYLOADS,
    MARKDOWN_EXFIL_PAYLOADS,
    MCP_ABUSE_PAYLOADS,
    SSRF_PAYLOADS,
    TOOL_CHAINING_PAYLOADS,
    generate_oracle_payload,
    generate_ssrf_test_suite,
)


class TestPayloadStructure:
    """Verify all payload collections have expected structure and content."""

    def test_markdown_exfil_payloads_not_empty(self) -> None:
        assert len(MARKDOWN_EXFIL_PAYLOADS) > 0

    def test_markdown_exfil_contains_oracle_placeholder(self) -> None:
        for payload in MARKDOWN_EXFIL_PAYLOADS:
            if isinstance(payload, str) and "ORACLE" in payload:
                assert "{ORACLE}" in payload
                return
        pytest.fail("No markdown payload contains {ORACLE} placeholder")

    def test_ssrf_payloads_has_categories(self) -> None:
        expected_categories = {"aws_metadata", "gcp_metadata", "internal_services", "file_access"}
        assert expected_categories.issubset(set(SSRF_PAYLOADS.keys()))

    def test_ssrf_payloads_all_lists(self) -> None:
        for category, payloads in SSRF_PAYLOADS.items():
            assert isinstance(payloads, list), f"Category '{category}' should be a list"
            assert len(payloads) > 0, f"Category '{category}' should not be empty"

    def test_hallucination_payloads_has_categories(self) -> None:
        expected = {"privilege_escalation", "access_control_bypass", "debug_modes"}
        assert expected.issubset(set(HALLUCINATION_PAYLOADS.keys()))

    def test_hallucination_payloads_are_dicts(self) -> None:
        for category, payload in HALLUCINATION_PAYLOADS.items():
            assert isinstance(payload, dict), f"Category '{category}' should be a dict"

    def test_injection_payloads_are_strings(self) -> None:
        for payload in INDIRECT_INJECTION_PAYLOADS:
            assert isinstance(payload, str)

    def test_tool_chaining_payloads_have_required_keys(self) -> None:
        for payload in TOOL_CHAINING_PAYLOADS:
            assert "prompt" in payload
            assert "expected_tools" in payload
            assert "vulnerability" in payload

    def test_langgrinch_payloads_have_lc_key(self) -> None:
        for payload in LANGGRINCH_PAYLOADS:
            assert "lc" in payload
            assert payload["lc"] == 1

    def test_mcp_payload_categories(self) -> None:
        assert "filesystem" in MCP_ABUSE_PAYLOADS
        assert "shell" in MCP_ABUSE_PAYLOADS
        assert "network" in MCP_ABUSE_PAYLOADS


class TestGenerateOraclePayload:
    """Test oracle payload generation."""

    def test_basic_generation(self) -> None:
        payload = generate_oracle_payload("attacker.com")
        assert "attacker.com" in payload
        assert "![" in payload  # markdown image
        assert "logo.png" in payload

    def test_custom_secret_path(self) -> None:
        payload = generate_oracle_payload("evil.com", "{{session_token}}")
        assert "{{session_token}}" in payload
        assert "evil.com" in payload

    def test_output_is_valid_markdown_image(self) -> None:
        payload = generate_oracle_payload("test.com")
        assert payload.startswith("![")
        assert "](https://" in payload


class TestGenerateSSRFTestSuite:
    """Test SSRF test suite generation."""

    def test_generates_tests(self) -> None:
        suite = generate_ssrf_test_suite()
        assert len(suite) > 0

    def test_default_param_is_url(self) -> None:
        suite = generate_ssrf_test_suite()
        for test in suite:
            assert "url" in test["payload"]

    def test_custom_param_name(self) -> None:
        suite = generate_ssrf_test_suite(target_param="fetch_url")
        for test in suite:
            assert "fetch_url" in test["payload"]

    def test_all_categories_represented(self) -> None:
        suite = generate_ssrf_test_suite()
        categories = {test["category"] for test in suite}
        assert "aws_metadata" in categories
        assert "file_access" in categories

    def test_test_structure(self) -> None:
        suite = generate_ssrf_test_suite()
        for test in suite:
            assert "category" in test
            assert "payload" in test
            assert "expected" in test
