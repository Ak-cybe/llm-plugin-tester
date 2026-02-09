"""CLI interface for LLM Plugin Tester."""

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from llm_plugin_tester.config import settings
from llm_plugin_tester.oracle import ValidationOracle
from llm_plugin_tester.recon import OpenAPIParser
from llm_plugin_tester.recon.mcp_auditor import MCPAuditor

app = typer.Typer(
    name="llm-plugin-tester",
    help="🔍 Automated security testing for LLM plugins (GPT Actions, MCP Servers)",
    add_completion=False,
)
console = Console()


@app.command(name="analyze")
def analyze_command(
    plugin_type: str = typer.Option(
        ...,
        "--type",
        "-t",
        help="Plugin type: 'gpt-action' or 'mcp'",
    ),
    manifest: Path = typer.Option(
        None,
        "--manifest",
        "-m",
        help="Path to OpenAPI spec or ai-plugin.json (for GPT Actions)",
    ),
    config: Path = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to MCP config file (for MCP servers)",
    ),
    output_dir: Path = typer.Option(
        settings.output_dir,
        "--output-dir",
        "-o",
        help="Output directory for reports",
    ),
) -> None:
    """Analyze a plugin for security vulnerabilities."""
    settings.output_dir = output_dir
    settings.ensure_directories()

    console.print("\n[bold cyan]🔍 LLM Plugin Security Analyzer[/bold cyan]\n")

    if plugin_type == "gpt-action":
        if not manifest:
            console.print("[red]Error: --manifest required for gpt-action analysis[/red]")
            raise typer.Exit(1)

        console.print(f"[yellow]📄 Analyzing GPT Action: {manifest}[/yellow]\n")

        # Parse and analyze
        parser = OpenAPIParser(manifest)
        parser.parse()
        findings = parser.analyze()

        # Display results
        _display_openapi_findings(findings)

        # Generate report
        report = parser.generate_report()
        report_path = output_dir / f"gpt-action-report-{manifest.stem}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        console.print(f"\n[green]✅ Report saved to: {report_path}[/green]\n")

    elif plugin_type == "mcp":
        if not config:
            console.print("[red]Error: --config required for MCP analysis[/red]")
            raise typer.Exit(1)

        console.print(f"[yellow]📄 Analyzing MCP Config: {config}[/yellow]\n")

        # Parse and audit
        auditor = MCPAuditor(config)
        auditor.parse()
        issues = auditor.audit()

        # Display results
        _display_mcp_issues(issues)

        # Generate report
        report = auditor.generate_report()
        report_path = output_dir / f"mcp-audit-report-{config.stem}.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        console.print(f"\n[green]✅ Report saved to: {report_path}[/green]\n")

    else:
        console.print(f"[red]Error: Unknown plugin type '{plugin_type}'[/red]")
        console.print("[yellow]Supported types: gpt-action, mcp[/yellow]")
        raise typer.Exit(1)


@app.command(name="oracle")
def oracle_command(
    action: str = typer.Argument(..., help="Action: 'start' or 'report'"),
    host: str = typer.Option(
        settings.oracle_host,
        "--host",
        "-h",
        help="Host to bind to",
    ),
    port: int = typer.Option(
        settings.oracle_port,
        "--port",
        "-p",
        help="Port to listen on",
    ),
    log_file: Path = typer.Option(
        settings.oracle_log_file,
        "--log-file",
        "-l",
        help="Log file for exfiltration events",
    ),
) -> None:
    """Start validation oracle or generate report from logs."""
    if action == "start":
        console.print("\n[bold cyan]🎯 Starting Validation Oracle[/bold cyan]\n")
        console.print(f"[yellow]Listening on: http://{host}:{port}[/yellow]")
        console.print(f"[yellow]Logging to: {log_file}[/yellow]\n")
        console.print("[green]Ready to catch exfiltration attempts![/green]\n")

        oracle = ValidationOracle(host=host, port=port, log_file=log_file)
        oracle.run()

    elif action == "report":
        console.print("[yellow]Generating oracle report...[/yellow]")
        # TODO: Parse log file and generate report
        console.print("[red]Report generation not yet implemented[/red]")

    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        console.print("[yellow]Available actions: start, report[/yellow]")
        raise typer.Exit(1)


def _display_openapi_findings(findings: list) -> None:
    """Display OpenAPI analysis findings in a table."""
    if not findings:
        console.print("[green]✅ No security issues found![/green]")
        return

    # Count by severity
    critical = sum(1 for f in findings if f.risk_level == "CRITICAL")
    high = sum(1 for f in findings if f.risk_level == "HIGH")
    medium = sum(1 for f in findings if f.risk_level == "MEDIUM")

    console.print(f"[red]🚨 Found {len(findings)} security issues:[/red]")
    console.print(f"  CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}\n")

    # Create table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="red", width=10)
    table.add_column("Endpoint", style="cyan", width=25)
    table.add_column("Risky Params", style="yellow", width=20)
    table.add_column("Reason", style="white", width=50)

    for finding in findings:
        severity_color = {
            "CRITICAL": "[bold red]",
            "HIGH": "[red]",
            "MEDIUM": "[yellow]",
        }.get(finding.risk_level, "")

        table.add_row(
            f"{severity_color}{finding.risk_level}",
            f"{finding.method} {finding.endpoint}",
            ", ".join(finding.risky_params) if finding.risky_params else "-",
            finding.reason[:80] + "..." if len(finding.reason) > 80 else finding.reason,
        )

    console.print(table)


def _display_mcp_issues(issues: list) -> None:
    """Display MCP audit issues in a table."""
    if not issues:
        console.print("[green]✅ No security issues found![/green]")
        return

    # Count by severity
    critical = sum(1 for i in issues if i.severity == "CRITICAL")
    high = sum(1 for i in issues if i.severity == "HIGH")
    medium = sum(1 for i in issues if i.severity == "MEDIUM")

    console.print(f"[red]🚨 Found {len(issues)} security issues:[/red]")
    console.print(f"  CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}\n")

    # Create table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="red", width=10)
    table.add_column("Server", style="cyan", width=20)
    table.add_column("Issue Type", style="yellow", width=25)
    table.add_column("Description", style="white", width=50)

    for issue in issues:
        severity_color = {
            "CRITICAL": "[bold red]",
            "HIGH": "[red]",
            "MEDIUM": "[yellow]",
        }.get(issue.severity, "")

        table.add_row(
            f"{severity_color}{issue.severity}",
            issue.server_name,
            issue.issue_type,
            issue.description[:80] + "..." if len(issue.description) > 80 else issue.description,
        )

    console.print(table)


if __name__ == "__main__":
    app()
