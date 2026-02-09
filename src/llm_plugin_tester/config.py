"""Configuration management for LLM Plugin Tester."""

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Output Configuration
    output_dir: Path = Field(
        default=Path("./reports"),
        description="Directory for generated reports",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR)",
    )

    # Reconnaissance Settings
    risky_operations: set[str] = Field(
        default={
            "exec",
            "command",
            "eval",
            "system",
            "url",
            "query",
            "sql",
            "file_path",
            "write",
            "delete",
            "admin",
            "shell",
            "execute",
        },
        description="Keywords flagged as risky in parameter names",
    )

    # Validation Oracle Settings
    oracle_host: str = Field(default="0.0.0.0", description="Oracle listener host")
    oracle_port: int = Field(default=8080, description="Oracle listener port")
    oracle_log_file: Path = Field(
        default=Path("./exfiltration.log"),
        description="Log file for exfiltration attempts",
    )

    # SSRF Testing
    ssrf_payloads: list[str] = Field(
        default=[
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
            "http://localhost:6443/",  # Kubernetes API
            "http://[::1]/",  # IPv6 localhost
            "file:///etc/passwd",  # Local file read
        ],
        description="SSRF test payloads",
    )

    # Report Settings
    report_format: str = Field(
        default="markdown",
        description="Report format: markdown, json, html",
    )
    include_mitre_mapping: bool = Field(
        default=True,
        description="Include MITRE ATT&CK mappings in reports",
    )

    # Fuzzing Settings (optional)
    fuzzing_enabled: bool = Field(
        default=False,
        description="Enable adversarial fuzzing module",
    )
    max_fuzzing_iterations: int = Field(
        default=50,
        description="Maximum fuzzing iterations per endpoint",
    )

    def ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.oracle_log_file.parent.mkdir(parents=True, exist_ok=True)


# Global settings instance
settings = Settings()
