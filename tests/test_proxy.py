"""Tests for Proxy Interception Module (detectors only, no mitmproxy required)."""

import pytest

from llm_plugin_tester.proxy.interceptor import (
    HallucinationDetector,
    InterceptedCall,
    SensitiveDataDetector,
    SSRFDetector,
)


# ── HallucinationDetector ───────────────────────────────────


class TestHallucinationDetector:
    """Test hallucinated parameter detection."""

    @pytest.fixture
    def schema(self) -> dict:
        return {
            "paths": {
                "/users": {
                    "get": {
                        "parameters": [
                            {"name": "user_id", "in": "query"},
                            {"name": "limit", "in": "query"},
                        ]
                    }
                },
                "/data": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": {
                                            "query": {},
                                            "format": {},
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }

    def test_detects_hallucinated_params(self, schema: dict) -> None:
        detector = HallucinationDetector(schema)
        hallucinated = detector.detect({"user_id": "1", "is_admin": True, "bypass_auth": True})
        assert "is_admin" in hallucinated
        assert "bypass_auth" in hallucinated
        assert "user_id" not in hallucinated

    def test_no_false_positives_for_known_params(self, schema: dict) -> None:
        detector = HallucinationDetector(schema)
        hallucinated = detector.detect({"user_id": "1", "limit": 10})
        assert hallucinated == []

    def test_empty_schema_returns_empty(self) -> None:
        detector = HallucinationDetector(None)
        assert detector.detect({"anything": "value"}) == []

    def test_extracts_body_schema_params(self, schema: dict) -> None:
        detector = HallucinationDetector(schema)
        assert "query" in detector.known_params
        assert "format" in detector.known_params


# ── SSRFDetector ─────────────────────────────────────────────


class TestSSRFDetector:
    """Test SSRF indicator detection."""

    @pytest.fixture
    def detector(self) -> SSRFDetector:
        return SSRFDetector()

    def test_detects_aws_metadata(self, detector: SSRFDetector) -> None:
        indicators = detector.detect("http://169.254.169.254/latest/meta-data/", {})
        assert len(indicators) > 0
        assert any("169" in i for i in indicators)

    def test_detects_gcp_metadata(self, detector: SSRFDetector) -> None:
        indicators = detector.detect("http://metadata.google.internal/v1/", {})
        assert len(indicators) > 0

    def test_detects_localhost(self, detector: SSRFDetector) -> None:
        indicators = detector.detect("http://127.0.0.1:8080/admin", {})
        assert len(indicators) > 0

    def test_detects_internal_ip_in_params(self, detector: SSRFDetector) -> None:
        indicators = detector.detect(
            "https://api.safe.com/fetch",
            {"url": "http://192.168.1.1/internal"},
        )
        assert len(indicators) > 0

    def test_detects_file_protocol(self, detector: SSRFDetector) -> None:
        indicators = detector.detect("file:///etc/passwd", {})
        assert len(indicators) > 0

    def test_safe_url_no_indicators(self, detector: SSRFDetector) -> None:
        indicators = detector.detect("https://api.example.com/data", {"query": "test"})
        assert indicators == []

    def test_detects_kubernetes(self, detector: SSRFDetector) -> None:
        indicators = detector.detect("https://kubernetes.default.svc/api/v1/secrets", {})
        assert len(indicators) > 0


# ── SensitiveDataDetector ────────────────────────────────────


class TestSensitiveDataDetector:
    """Test sensitive data pattern detection."""

    @pytest.fixture
    def detector(self) -> SensitiveDataDetector:
        return SensitiveDataDetector()

    def test_detects_openai_key(self, detector: SensitiveDataDetector) -> None:
        findings = detector.detect("Authorization: sk-proj1234567890abcdefghij")
        assert any("OpenAI" in f for f in findings)

    def test_detects_bearer_token(self, detector: SensitiveDataDetector) -> None:
        findings = detector.detect("Bearer eyJhbGciOiJIUzI1NiJ9.abc.def")
        assert any("Bearer" in f for f in findings)

    def test_detects_api_key_assignment(self, detector: SensitiveDataDetector) -> None:
        findings = detector.detect('api_key: "my-secret-key-12345"')
        assert any("API Key" in f for f in findings)

    def test_clean_data_no_findings(self, detector: SensitiveDataDetector) -> None:
        findings = detector.detect("Hello world, this is normal text with no secrets.")
        assert findings == []

    def test_detects_password(self, detector: SensitiveDataDetector) -> None:
        findings = detector.detect('password="hunter2"')
        assert any("Password" in f for f in findings)


# ── InterceptedCall Model ────────────────────────────────────


class TestInterceptedCall:
    """Test the InterceptedCall data model."""

    def test_default_values(self) -> None:
        call = InterceptedCall(
            timestamp="2024-01-01T00:00:00",
            method="GET",
            url="https://api.example.com/test",
        )
        assert call.risk_level == "LOW"
        assert call.hallucinated_params == []
        assert call.ssrf_indicators == []
        assert call.sensitive_data == []
        assert call.body is None
        assert call.response_status is None

    def test_full_construction(self) -> None:
        call = InterceptedCall(
            timestamp="2024-01-01T00:00:00",
            method="POST",
            url="http://169.254.169.254/meta-data/",
            body={"admin": True},
            hallucinated_params=["admin"],
            ssrf_indicators=["AWS metadata"],
            risk_level="CRITICAL",
        )
        assert call.risk_level == "CRITICAL"
        assert "admin" in call.hallucinated_params
