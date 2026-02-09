"""Tests for OpenAPI Parser."""

import json
from pathlib import Path

import pytest

from llm_plugin_tester.recon import OpenAPIParser


@pytest.fixture
def sample_openapi_spec(tmp_path: Path) -> Path:
    """Create a sample OpenAPI spec with vulnerabilities."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/execute": {
                "post": {
                    "operationId": "executeCommand",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "command": {"type": "string"},
                                        "shell": {"type": "boolean"},
                                    },
                                }
                            }
                        }
                    },
                }
            },
            "/query": {
                "get": {
                    "operationId": "queryData",
                    "parameters": [
                        {
                            "name": "url",
                            "in": "query",
                            "schema": {"type": "string"},
                        }
                    ],
                }
            },
        },
    }

    spec_path = tmp_path / "test-spec.json"
    with open(spec_path, "w", encoding="utf-8") as f:
        json.dump(spec, f)

    return spec_path


def test_parser_initialization(sample_openapi_spec: Path) -> None:
    """Test parser can be initialized."""
    parser = OpenAPIParser(sample_openapi_spec)
    assert parser.manifest_path == sample_openapi_spec
    assert parser.findings == []


def test_parse_openapi_spec(sample_openapi_spec: Path) -> None:
    """Test parsing OpenAPI specification."""
    parser = OpenAPIParser(sample_openapi_spec)
    spec = parser.parse()

    assert "openapi" in spec
    assert "paths" in spec
    assert "/execute" in spec["paths"]


def test_detect_risky_parameters(sample_openapi_spec: Path) -> None:
    """Test detection of risky parameter names."""
    parser = OpenAPIParser(sample_openapi_spec)
    parser.parse()
    findings = parser.analyze()

    # Should find risky params: command, shell, url
    risky_findings = [f for f in findings if f.risky_params]
    assert len(risky_findings) > 0

    # Check for command execution risk
    command_findings = [f for f in findings if "command" in f.risky_params]
    assert len(command_findings) > 0
    assert command_findings[0].risk_level in ["CRITICAL", "HIGH"]


def test_report_generation(sample_openapi_spec: Path) -> None:
    """Test report generation."""
    parser = OpenAPIParser(sample_openapi_spec)
    parser.parse()
    parser.analyze()

    report = parser.generate_report()

    assert "total_findings" in report
    assert "critical_count" in report
    assert "findings" in report
    assert isinstance(report["findings"], list)


def test_gpt_action_no_auth(tmp_path: Path) -> None:
    """Test detection of GPT Action with no authentication."""
    plugin_manifest = {
        "schema_version": "v1",
        "name_for_model": "test",
        "auth": {"type": "none"},
        "api": {"type": "openapi"},
    }

    manifest_path = tmp_path / "ai-plugin.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(plugin_manifest, f)

    parser = OpenAPIParser(manifest_path)
    parser.parse()
    findings = parser.analyze()

    # Should flag no authentication
    no_auth_findings = [f for f in findings if "No authentication" in f.reason]
    assert len(no_auth_findings) > 0
    assert no_auth_findings[0].risk_level == "HIGH"
