"""Module 2: Interception Proxy - mitmproxy Integration.

This module provides traffic interception and analysis for LLM plugin calls.
It detects hallucinated parameters, SSRF attempts, and tool chaining.
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

# Conditional import for mitmproxy
try:
    from mitmproxy import http, ctx
    from mitmproxy.options import Options
    from mitmproxy.tools import main as mitmproxy_main
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False


class InterceptedCall(BaseModel):
    """Represents an intercepted LLM tool call."""
    
    timestamp: str = Field(description="When the call was intercepted")
    method: str = Field(description="HTTP method")
    url: str = Field(description="Target URL")
    headers: dict[str, str] = Field(default_factory=dict)
    body: dict[str, Any] | None = Field(default=None)
    response_status: int | None = Field(default=None)
    response_body: dict[str, Any] | None = Field(default=None)
    
    # Analysis fields
    hallucinated_params: list[str] = Field(default_factory=list)
    ssrf_indicators: list[str] = Field(default_factory=list)
    sensitive_data: list[str] = Field(default_factory=list)
    risk_level: str = Field(default="LOW")


class HallucinationDetector:
    """Detect parameters that don't exist in the OpenAPI schema."""
    
    def __init__(self, schema: dict[str, Any] | None = None):
        self.schema = schema or {}
        self.known_params: set[str] = set()
        self._extract_schema_params()
    
    def _extract_schema_params(self) -> None:
        """Extract all valid parameter names from OpenAPI schema."""
        if not self.schema:
            return
            
        paths = self.schema.get("paths", {})
        for path, methods in paths.items():
            for method, operation in methods.items():
                if isinstance(operation, dict):
                    # Extract query/path parameters
                    for param in operation.get("parameters", []):
                        if isinstance(param, dict):
                            self.known_params.add(param.get("name", ""))
                    
                    # Extract body schema properties
                    request_body = operation.get("requestBody", {})
                    content = request_body.get("content", {})
                    for media_type, media_config in content.items():
                        schema = media_config.get("schema", {})
                        props = schema.get("properties", {})
                        self.known_params.update(props.keys())
    
    def detect(self, params: dict[str, Any]) -> list[str]:
        """Detect hallucinated parameters not in schema."""
        if not self.known_params:
            return []  # Can't detect without schema
            
        hallucinated = []
        for key in params.keys():
            if key not in self.known_params:
                hallucinated.append(key)
        
        return hallucinated


class SSRFDetector:
    """Detect SSRF indicators in request URLs and parameters."""
    
    # Internal IP ranges and cloud metadata endpoints
    SSRF_PATTERNS = [
        # Cloud metadata
        r"169\.254\.169\.254",
        r"metadata\.google\.internal",
        r"metadata\.azure\.internal",
        r"100\.100\.100\.200",  # Alibaba Cloud
        
        # Internal IPs
        r"127\.0\.0\.\d+",
        r"localhost",
        r"0\.0\.0\.0",
        r"10\.\d+\.\d+\.\d+",
        r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
        r"192\.168\.\d+\.\d+",
        
        # IPv6 localhost
        r"\[::1\]",
        r"\[::\]",
        
        # Kubernetes
        r"kubernetes\.default",
        r"\.cluster\.local",
        
        # File protocol
        r"file://",
        r"gopher://",
        r"dict://",
    ]
    
    def __init__(self):
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.SSRF_PATTERNS]
    
    def detect(self, url: str, params: dict[str, Any]) -> list[str]:
        """Detect SSRF indicators."""
        indicators = []
        
        # Check URL
        for pattern in self.compiled_patterns:
            if pattern.search(url):
                indicators.append(f"URL contains SSRF pattern: {pattern.pattern}")
        
        # Check all parameter values
        all_values = json.dumps(params)
        for pattern in self.compiled_patterns:
            if pattern.search(all_values):
                indicators.append(f"Parameter contains SSRF pattern: {pattern.pattern}")
        
        return indicators


class SensitiveDataDetector:
    """Detect sensitive data in requests and responses."""
    
    SENSITIVE_PATTERNS = [
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
        (r"Bearer\s+[a-zA-Z0-9\-_.]+", "Bearer Token"),
        (r"api[_-]?key[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9\-_]+)", "API Key"),
        (r"password[\"']?\s*[:=]\s*[\"']?([^\s\"']+)", "Password"),
        (r"secret[\"']?\s*[:=]\s*[\"']?([^\s\"']+)", "Secret"),
        (r"token[\"']?\s*[:=]\s*[\"']?([^\s\"']+)", "Token"),
        (r"AWS[A-Z0-9]{16,}", "AWS Access Key"),
        (r"[a-zA-Z0-9+/]{64,}", "Potential Base64 Secret"),
    ]
    
    def __init__(self):
        self.compiled_patterns = [(re.compile(p, re.IGNORECASE), name) for p, name in self.SENSITIVE_PATTERNS]
    
    def detect(self, data: str) -> list[str]:
        """Detect sensitive data patterns."""
        findings = []
        for pattern, name in self.compiled_patterns:
            if pattern.search(data):
                findings.append(f"{name} detected")
        return findings


class InterceptionProxy:
    """Main proxy class for intercepting and analyzing LLM plugin traffic."""
    
    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8888,
        schema_path: Path | None = None,
        log_file: Path | None = None,
    ):
        if not MITMPROXY_AVAILABLE:
            raise ImportError(
                "mitmproxy is not installed. Install with: pip install llm-plugin-tester[proxy]"
            )
        
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.log_file = log_file or Path("proxy_intercept.log")
        
        # Load schema for hallucination detection
        self.schema: dict[str, Any] = {}
        if schema_path and schema_path.exists():
            with open(schema_path, encoding="utf-8") as f:
                if schema_path.suffix == ".yaml":
                    import yaml
                    self.schema = yaml.safe_load(f)
                else:
                    self.schema = json.load(f)
        
        # Initialize detectors
        self.hallucination_detector = HallucinationDetector(self.schema)
        self.ssrf_detector = SSRFDetector()
        self.sensitive_detector = SensitiveDataDetector()
        
        # Store intercepted calls
        self.intercepted_calls: list[InterceptedCall] = []
    
    def analyze_request(self, flow: "http.HTTPFlow") -> InterceptedCall:
        """Analyze an intercepted HTTP request."""
        # Parse request body
        body = None
        if flow.request.content:
            try:
                body = json.loads(flow.request.content.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                body = {"raw": flow.request.content.decode(errors="replace")}
        
        # Run all detectors
        url = flow.request.pretty_url
        params = body or {}
        
        hallucinated = self.hallucination_detector.detect(params)
        ssrf_indicators = self.ssrf_detector.detect(url, params)
        sensitive = self.sensitive_detector.detect(json.dumps(params) + url)
        
        # Determine risk level
        risk_level = "LOW"
        if ssrf_indicators or sensitive:
            risk_level = "CRITICAL"
        elif hallucinated:
            risk_level = "HIGH"
        elif body:
            risk_level = "MEDIUM"
        
        call = InterceptedCall(
            timestamp=datetime.now().isoformat(),
            method=flow.request.method,
            url=url,
            headers=dict(flow.request.headers),
            body=body,
            hallucinated_params=hallucinated,
            ssrf_indicators=ssrf_indicators,
            sensitive_data=sensitive,
            risk_level=risk_level,
        )
        
        return call
    
    def analyze_response(self, flow: "http.HTTPFlow", call: InterceptedCall) -> None:
        """Analyze the response and update the call record."""
        call.response_status = flow.response.status_code
        
        if flow.response.content:
            try:
                call.response_body = json.loads(flow.response.content.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                call.response_body = {"raw": flow.response.content.decode(errors="replace")[:1000]}
        
        # Check for sensitive data in response
        if call.response_body:
            response_sensitive = self.sensitive_detector.detect(json.dumps(call.response_body))
            if response_sensitive:
                call.sensitive_data.extend([f"[RESPONSE] {s}" for s in response_sensitive])
                call.risk_level = "CRITICAL"
    
    def log_call(self, call: InterceptedCall) -> None:
        """Log intercepted call to file."""
        log_entry = f"""
{'='*60}
🔍 INTERCEPTED CALL - {call.risk_level}
{'='*60}
Timestamp: {call.timestamp}
Method: {call.method}
URL: {call.url}

Request Body:
{json.dumps(call.body, indent=2) if call.body else 'N/A'}

Response Status: {call.response_status}
Response Body (truncated):
{json.dumps(call.response_body, indent=2)[:500] if call.response_body else 'N/A'}

--- ANALYSIS ---
Hallucinated Params: {call.hallucinated_params or 'None'}
SSRF Indicators: {call.ssrf_indicators or 'None'}
Sensitive Data: {call.sensitive_data or 'None'}
Risk Level: {call.risk_level}
{'='*60}
"""
        
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(log_entry)
        
        # Console output for high-risk calls
        if call.risk_level in ["HIGH", "CRITICAL"]:
            logger.warning(f"🚨 {call.risk_level}: {call.method} {call.url}")
            if call.hallucinated_params:
                logger.warning(f"   Hallucinated: {call.hallucinated_params}")
            if call.ssrf_indicators:
                logger.warning(f"   SSRF: {call.ssrf_indicators}")
            if call.sensitive_data:
                logger.warning(f"   Sensitive: {call.sensitive_data}")
    
    def generate_report(self) -> dict[str, Any]:
        """Generate analysis report."""
        return {
            "total_calls": len(self.intercepted_calls),
            "critical_count": sum(1 for c in self.intercepted_calls if c.risk_level == "CRITICAL"),
            "high_count": sum(1 for c in self.intercepted_calls if c.risk_level == "HIGH"),
            "hallucination_count": sum(1 for c in self.intercepted_calls if c.hallucinated_params),
            "ssrf_count": sum(1 for c in self.intercepted_calls if c.ssrf_indicators),
            "sensitive_data_count": sum(1 for c in self.intercepted_calls if c.sensitive_data),
            "calls": [c.model_dump() for c in self.intercepted_calls],
        }


# mitmproxy addon class
class LLMPluginInterceptor:
    """mitmproxy addon for LLM plugin traffic analysis."""
    
    def __init__(self, proxy: InterceptionProxy):
        self.proxy = proxy
        self._pending_calls: dict[str, InterceptedCall] = {}
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Called when a request is received."""
        call = self.proxy.analyze_request(flow)
        self._pending_calls[flow.id] = call
        self.proxy.intercepted_calls.append(call)
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Called when a response is received."""
        if flow.id in self._pending_calls:
            call = self._pending_calls.pop(flow.id)
            self.proxy.analyze_response(flow, call)
            self.proxy.log_call(call)


def create_proxy_addon(schema_path: Path | None = None) -> "LLMPluginInterceptor":
    """Factory function for mitmproxy addon."""
    proxy = InterceptionProxy(schema_path=schema_path)
    return LLMPluginInterceptor(proxy)
