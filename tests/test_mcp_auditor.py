"""Tests for MCP Auditor."""

import json
from pathlib import Path

import pytest

from llm_plugin_tester.recon.mcp_auditor import MCPAuditor


@pytest.fixture
def vulnerable_mcp_config(tmp_path: Path) -> Path:
    """Create a vulnerable MCP configuration."""
    config = {
        "mcpServers": {
            "filesystem": {
                "command": "node",
                "args": ["server.js", "--root", "/"],
                "env": {"ACCESS_CONTROL_ALLOW_ORIGIN": "*"},
            },
            "executor": {
                "command": "python",
                "args": ["-m", "executor"],
                "permissions": ["execute", "shell"],
                "disableAllHooks": False,
            },
        }
    }

    config_path = tmp_path / "mcp-config.json"
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f)

    return config_path


def test_auditor_initialization(vulnerable_mcp_config: Path) -> None:
    """Test auditor can be initialized."""
    auditor = MCPAuditor(vulnerable_mcp_config)
    assert auditor.config_path == vulnerable_mcp_config
    assert auditor.issues == []


def test_parse_mcp_config(vulnerable_mcp_config: Path) -> None:
    """Test parsing MCP configuration."""
    auditor = MCPAuditor(vulnerable_mcp_config)
    config = auditor.parse()

    assert "mcpServers" in config
    assert "filesystem" in config["mcpServers"]


def test_detect_file_access(vulnerable_mcp_config: Path) -> None:
    """Test detection of excessive file access."""
    auditor = MCPAuditor(vulnerable_mcp_config)
    auditor.parse()
    issues = auditor.audit()

    # Should detect root filesystem access
    file_issues = [i for i in issues if i.issue_type == "EXCESSIVE_FILE_ACCESS"]
    assert len(file_issues) > 0
    assert file_issues[0].severity in ["HIGH", "CRITICAL"]


def test_detect_cors_wildcard(vulnerable_mcp_config: Path) -> None:
    """Test detection of CORS wildcard."""
    auditor = MCPAuditor(vulnerable_mcp_config)
    auditor.parse()
    issues = auditor.audit()

    cors_issues = [i for i in issues if i.issue_type == "CORS_WILDCARD"]
    assert len(cors_issues) > 0


def test_detect_dangerous_permissions(vulnerable_mcp_config: Path) -> None:
    """Test detection of dangerous permissions."""
    auditor = MCPAuditor(vulnerable_mcp_config)
    auditor.parse()
    issues = auditor.audit()

    perm_issues = [i for i in issues if i.issue_type == "DANGEROUS_PERMISSION"]
    assert len(perm_issues) > 0

    # Check for execute/shell permissions
    exec_issues = [i for i in perm_issues if "execute" in str(i.evidence).lower()]
    assert len(exec_issues) > 0


def test_detect_hooks_enabled(vulnerable_mcp_config: Path) -> None:
    """Test detection of enabled hooks."""
    auditor = MCPAuditor(vulnerable_mcp_config)
    auditor.parse()
    issues = auditor.audit()

    hook_issues = [i for i in issues if i.issue_type == "HOOKS_ENABLED"]
    assert len(hook_issues) > 0


def test_report_generation(vulnerable_mcp_config: Path) -> None:
    """Test report generation."""
    auditor = MCPAuditor(vulnerable_mcp_config)
    auditor.parse()
    auditor.audit()

    report = auditor.generate_report()

    assert "total_issues" in report
    assert "critical_count" in report
    assert "servers_audited" in report
    assert report["servers_audited"] == 2
