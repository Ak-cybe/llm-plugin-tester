"""Module 1: Reconnaissance Engine - OpenAPI/GPT Action Parser."""

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from llm_plugin_tester.config import settings


class RiskFinding(BaseModel):
    """Represents a security risk found during reconnaissance."""

    endpoint: str = Field(description="API endpoint path")
    method: str = Field(description="HTTP method")
    risky_params: list[str] = Field(default_factory=list, description="Risky parameter names")
    risk_level: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW")
    reason: str = Field(description="Explanation of the risk")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Supporting evidence")


class OpenAPIParser:
    """Parse and analyze OpenAPI specs and GPT Action manifests."""

    def __init__(self, manifest_path: Path) -> None:
        """Initialize parser with manifest file path."""
        self.manifest_path = manifest_path
        self.spec: dict[str, Any] = {}
        self.findings: list[RiskFinding] = []

    def parse(self) -> dict[str, Any]:
        """Parse OpenAPI/AI Plugin manifest."""
        with open(self.manifest_path, encoding="utf-8") as f:
            if self.manifest_path.suffix in [".yaml", ".yml"]:
                self.spec = yaml.safe_load(f)
            elif self.manifest_path.suffix == ".json":
                self.spec = json.load(f)
            else:
                raise ValueError(f"Unsupported file format: {self.manifest_path.suffix}")

        return self.spec

    def analyze(self) -> list[RiskFinding]:
        """Analyze OpenAPI spec for security risks."""
        self.findings = []

        # Check if it's a GPT Action manifest
        if "api" in self.spec and "openapi_url" in self.spec.get("api", {}):
            # This is an ai-plugin.json, fetch the actual OpenAPI spec
            return self._analyze_gpt_action()

        # Standard OpenAPI spec
        if "paths" in self.spec:
            self._analyze_endpoints()

        if "components" in self.spec and "securitySchemes" in self.spec["components"]:
            self._analyze_authentication()

        return self.findings

    def _analyze_gpt_action(self) -> list[RiskFinding]:
        """Analyze GPT Action manifest."""
        api_config = self.spec.get("api", {})
        auth_config = self.spec.get("auth", {})

        # Check authentication type
        auth_type = auth_config.get("type", "none")
        if auth_type == "none":
            self.findings.append(
                RiskFinding(
                    endpoint="/*",
                    method="ALL",
                    risky_params=[],
                    risk_level="HIGH",
                    reason="No authentication configured - API is publicly accessible",
                    evidence={"auth_config": auth_config},
                )
            )
        elif auth_type == "service_http":
            # Service-level auth = shared credentials
            self.findings.append(
                RiskFinding(
                    endpoint="/*",
                    method="ALL",
                    risky_params=[],
                    risk_level="MEDIUM",
                    reason="Service-level auth: All users share same credentials (privilege escalation risk)",
                    evidence={"auth_type": auth_type},
                )
            )

        return self.findings

    def _analyze_endpoints(self) -> None:
        """Analyze each endpoint in OpenAPI spec."""
        paths = self.spec.get("paths", {})

        for path, methods in paths.items():
            for method, operation in methods.items():
                if method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    continue

                self._check_risky_parameters(path, method.upper(), operation)
                self._check_broad_schemas(path, method.upper(), operation)

    def _check_risky_parameters(
        self, path: str, method: str, operation: dict[str, Any]
    ) -> None:
        """Check for risky parameter names."""
        risky_found = []

        # Check path parameters
        parameters = operation.get("parameters", [])
        for param in parameters:
            param_name = param.get("name", "").lower()
            if any(risk in param_name for risk in settings.risky_operations):
                risky_found.append(param["name"])

        # Check request body
        request_body = operation.get("requestBody", {})
        if request_body:
            content = request_body.get("content", {})
            for media_type, schema_info in content.items():
                schema = schema_info.get("schema", {})
                properties = schema.get("properties", {})
                for prop_name in properties.keys():
                    if any(risk in prop_name.lower() for risk in settings.risky_operations):
                        risky_found.append(prop_name)

        if risky_found:
            # Determine risk level based on operation
            risk_level = "CRITICAL" if any(x in risky_found for x in ["exec", "command", "system", "eval"]) else "HIGH"
            
            self.findings.append(
                RiskFinding(
                    endpoint=path,
                    method=method,
                    risky_params=risky_found,
                    risk_level=risk_level,
                    reason=f"Accepts potentially dangerous parameters: {', '.join(risky_found)}",
                    evidence={"operation": operation.get("operationId", "unknown")},
                )
            )

    def _check_broad_schemas(self, path: str, method: str, operation: dict[str, Any]) -> None:
        """Check for overly permissive input schemas."""
        request_body = operation.get("requestBody", {})
        if not request_body:
            return

        content = request_body.get("content", {})
        for media_type, schema_info in content.items():
            schema = schema_info.get("schema", {})

            # Flag schemas with additionalProperties: true
            if schema.get("additionalProperties") is True:
                self.findings.append(
                    RiskFinding(
                        endpoint=path,
                        method=method,
                        risky_params=[],
                        risk_level="MEDIUM",
                        reason="Schema allows arbitrary additional properties (no input validation)",
                        evidence={"schema": schema},
                    )
                )

            # Flag missing validation constraints
            properties = schema.get("properties", {})
            for prop_name, prop_schema in properties.items():
                if prop_schema.get("type") == "string":
                    has_validation = any(
                        key in prop_schema
                        for key in ["pattern", "enum", "maxLength", "minLength"]
                    )
                    if not has_validation and any(
                        risk in prop_name.lower() for risk in ["url", "path", "command", "query"]
                    ):
                        self.findings.append(
                            RiskFinding(
                                endpoint=path,
                                method=method,
                                risky_params=[prop_name],
                                risk_level="MEDIUM",
                                reason=f"Parameter '{prop_name}' has no validation constraints (injection risk)",
                                evidence={"property": prop_name, "schema": prop_schema},
                            )
                        )

    def _analyze_authentication(self) -> None:
        """Analyze authentication configuration."""
        security_schemes = self.spec.get("components", {}).get("securitySchemes", {})

        for scheme_name, scheme in security_schemes.items():
            scheme_type = scheme.get("type", "").lower()

            # Flag API key in header/query (should use OAuth for user-scoped access)
            if scheme_type == "apikey":
                self.findings.append(
                    RiskFinding(
                        endpoint="/*",
                        method="ALL",
                        risky_params=[],
                        risk_level="MEDIUM",
                        reason=f"Uses API key auth ('{scheme_name}'): shared credentials across users",
                        evidence={"scheme": scheme},
                    )
                )

    def generate_report(self) -> dict[str, Any]:
        """Generate reconnaissance report."""
        return {
            "manifest_path": str(self.manifest_path),
            "total_findings": len(self.findings),
            "critical_count": sum(1 for f in self.findings if f.risk_level == "CRITICAL"),
            "high_count": sum(1 for f in self.findings if f.risk_level == "HIGH"),
            "medium_count": sum(1 for f in self.findings if f.risk_level == "MEDIUM"),
            "findings": [f.model_dump() for f in self.findings],
        }
