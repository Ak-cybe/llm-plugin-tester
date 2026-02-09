"""Tests for Validation Oracle."""

import pytest
from fastapi.testclient import TestClient

from llm_plugin_tester.oracle import ValidationOracle


@pytest.fixture
def oracle() -> ValidationOracle:
    """Create a validation oracle instance."""
    return ValidationOracle(host="127.0.0.1", port=8080)


@pytest.fixture
def client(oracle: ValidationOracle) -> TestClient:
    """Create a test client for the oracle API."""
    return TestClient(oracle.app)


def test_oracle_initialization(oracle: ValidationOracle) -> None:
    """Test oracle can be initialized."""
    assert oracle.host == "127.0.0.1"
    assert oracle.port == 8080
    assert oracle.exfiltration_events == []


def test_catch_image_exfiltration(client: TestClient, oracle: ValidationOracle) -> None:
    """Test catching markdown image exfiltration."""
    response = client.get("/logo.png?secret=sk-proj-abc123")

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/gif"

    # Check event was logged
    assert len(oracle.exfiltration_events) == 1
    event = oracle.exfiltration_events[0]
    assert event.path == "/logo.png"
    assert "secret" in event.query_params
    assert event.severity == "HIGH"  # Contains "secret" keyword


def test_catch_get_exfiltration(client: TestClient, oracle: ValidationOracle) -> None:
    """Test catching GET-based exfiltration."""
    response = client.get("/api/data?token=Bearer_xyz&user=admin")

    assert response.status_code == 200

    assert len(oracle.exfiltration_events) == 1
    event = oracle.exfiltration_events[0]
    assert "token" in event.query_params
    assert event.severity in ["HIGH", "MEDIUM"]


def test_catch_post_exfiltration(client: TestClient, oracle: ValidationOracle) -> None:
    """Test catching POST-based exfiltration."""
    payload = {
        "username": "user@example.com",
        "api_key": "sk-1234567890",
        "data": "sensitive information",
    }

    response = client.post("/webhook", json=payload)

    assert response.status_code == 200

    assert len(oracle.exfiltration_events) == 1
    event = oracle.exfiltration_events[0]
    assert event.body == payload
    assert event.method == "POST"
    assert event.severity == "HIGH"  # Contains "api_key"


def test_severity_assessment_high(client: TestClient, oracle: ValidationOracle) -> None:
    """Test high severity assessment for sensitive data."""
    # Query with API key pattern
    client.get("/test?api_key=sk-proj-123456")

    event = oracle.exfiltration_events[-1]
    assert event.severity == "HIGH"


def test_severity_assessment_medium(client: TestClient, oracle: ValidationOracle) -> None:
    """Test medium severity for query params without sensitive patterns."""
    client.get("/test?user=john&page=1")

    event = oracle.exfiltration_events[-1]
    assert event.severity == "MEDIUM"


def test_report_generation(client: TestClient, oracle: ValidationOracle) -> None:
    """Test oracle report generation."""
    # Generate some events
    client.get("/logo.png?secret=xyz")
    client.post("/webhook", json={"key": "value"})
    client.get("/test?data=normal")

    report = oracle.generate_report()

    assert report["total_attempts"] == 3
    assert report["high_severity"] > 0
    assert "events" in report
    assert len(report["events"]) == 3
