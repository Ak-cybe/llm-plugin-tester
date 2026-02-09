"""Module 1: MCP Server Configuration Auditor."""

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class MCPIssue(BaseModel):
    """Represents a security issue in MCP configuration."""

    server_name: str = Field(description="Name of the MCP server")
    issue_type: str = Field(description="Type of security issue")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW")
    description: str = Field(description="Detailed description of the issue")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Supporting evidence")


class MCPAuditor:
    """Audit MCP (Model Context Protocol) server configurations."""

    def __init__(self, config_path: Path) -> None:
        """Initialize auditor with MCP config file path."""
        self.config_path = config_path
        self.config: dict[str, Any] = {}
        self.issues: list[MCPIssue] = []

    def parse(self) -> dict[str, Any]:
        """Parse MCP configuration file."""
        with open(self.config_path, encoding="utf-8") as f:
            self.config = json.load(f)
        return self.config

    def audit(self) -> list[MCPIssue]:
        """Audit MCP configuration for security issues."""
        self.issues = []

        # MCP configs can be in different formats
        if "mcpServers" in self.config:
            # Claude Desktop format
            servers = self.config["mcpServers"]
        elif "servers" in self.config:
            servers = self.config["servers"]
        else:
            servers = self.config

        for server_name, server_config in servers.items():
            self._check_file_access(server_name, server_config)
            self._check_network_scope(server_name, server_config)
            self._check_hooks(server_name, server_config)
            self._check_permissions(server_name, server_config)

        return self.issues

    def _check_file_access(self, server_name: str, config: dict[str, Any]) -> None:
        """Check for excessive file system access."""
        # Check command arguments for file paths
        args = config.get("args", [])
        command = config.get("command", "")

        dangerous_paths = ["/", "~", "C:\\", "D:\\", "*"]

        for arg in args:
            if isinstance(arg, str):
                for dangerous_path in dangerous_paths:
                    if dangerous_path in arg:
                        self.issues.append(
                            MCPIssue(
                                server_name=server_name,
                                issue_type="EXCESSIVE_FILE_ACCESS",
                                severity="HIGH",
                                description=f"Server has access to broad file path: {arg}",
                                evidence={"path": arg, "command": command},
                            )
                        )

        # Check for specific file access configs
        if "allowedPaths" in config:
            allowed = config["allowedPaths"]
            if isinstance(allowed, list) and any(p in str(allowed) for p in dangerous_paths):
                self.issues.append(
                    MCPIssue(
                        server_name=server_name,
                        issue_type="EXCESSIVE_FILE_ACCESS",
                        severity="HIGH",
                        description="Server has root filesystem access",
                        evidence={"allowedPaths": allowed},
                    )
                )

    def _check_network_scope(self, server_name: str, config: dict[str, Any]) -> None:
        """Check for overly permissive network access."""
        # Check for CORS wildcard
        env = config.get("env", {})
        if "ACCESS_CONTROL_ALLOW_ORIGIN" in env:
            if env["ACCESS_CONTROL_ALLOW_ORIGIN"] == "*":
                self.issues.append(
                    MCPIssue(
                        server_name=server_name,
                        issue_type="CORS_WILDCARD",
                        severity="MEDIUM",
                        description="CORS wildcard allows any origin to access server",
                        evidence={"env": env},
                    )
                )

        # Check for binding to all interfaces
        if "host" in config and config["host"] in ["0.0.0.0", "::"]:
            self.issues.append(
                MCPIssue(
                    server_name=server_name,
                    issue_type="NETWORK_EXPOSURE",
                    severity="MEDIUM",
                    description="Server binds to all network interfaces (external access risk)",
                    evidence={"host": config["host"]},
                )
            )

    def _check_hooks(self, server_name: str, config: dict[str, Any]) -> None:
        """Check for dangerous hook configurations."""
        # Check if hooks are enabled (persistence risk)
        if "disableAllHooks" in config and config["disableAllHooks"] is False:
            self.issues.append(
                MCPIssue(
                    server_name=server_name,
                    issue_type="HOOKS_ENABLED",
                    severity="MEDIUM",
                    description="Server hooks are enabled (persistence/backdoor risk)",
                    evidence={"disableAllHooks": False},
                )
            )

        # Check for pre/post execution hooks
        dangerous_hooks = ["preExec", "postExec", "onInstall", "onUpdate"]
        for hook in dangerous_hooks:
            if hook in config:
                self.issues.append(
                    MCPIssue(
                        server_name=server_name,
                        issue_type="DANGEROUS_HOOK",
                        severity="HIGH",
                        description=f"Server defines {hook} hook (code execution risk)",
                        evidence={hook: config[hook]},
                    )
                )

    def _check_permissions(self, server_name: str, config: dict[str, Any]) -> None:
        """Check for excessive permissions."""
        # Check capabilities/permissions field
        permissions = config.get("permissions", [])
        capabilities = config.get("capabilities", [])

        dangerous_perms = [
            "execute",
            "shell",
            "system",
            "admin",
            "root",
            "sudo",
        ]

        all_perms = permissions + capabilities
        for perm in all_perms:
            if isinstance(perm, str):
                perm_lower = perm.lower()
                if any(danger in perm_lower for danger in dangerous_perms):
                    self.issues.append(
                        MCPIssue(
                            server_name=server_name,
                            issue_type="DANGEROUS_PERMISSION",
                            severity="CRITICAL",
                            description=f"Server has dangerous permission: {perm}",
                            evidence={"permission": perm},
                        )
                    )

    def generate_report(self) -> dict[str, Any]:
        """Generate MCP audit report."""
        return {
            "config_path": str(self.config_path),
            "total_issues": len(self.issues),
            "critical_count": sum(1 for i in self.issues if i.severity == "CRITICAL"),
            "high_count": sum(1 for i in self.issues if i.severity == "HIGH"),
            "medium_count": sum(1 for i in self.issues if i.severity == "MEDIUM"),
            "servers_audited": len(self.config.get("mcpServers", self.config.get("servers", {}))),
            "issues": [i.model_dump() for i in self.issues],
        }
