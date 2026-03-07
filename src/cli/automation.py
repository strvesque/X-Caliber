"""Click-based automation CLI for X-Caliber with validation.

Enhanced CLI with URL validation, rate limiting flags, and proper error handling.
"""
# pyright: reportMissingImports=false, reportFunctionMemberAccess=false
from __future__ import annotations

import click  # type: ignore
import re
import asyncio
import json
from pathlib import Path
from typing import Optional, Tuple

from src.core.orchestrator import AutomationOrchestrator


def validate_target(ctx, param, value: Optional[str]) -> str:
    """Validate target URL/IP/domain."""
    if not value:
        raise click.BadParameter("Target is required")
    
    # Check if URL
    if value.startswith(('http://', 'https://')):
        return value
    
    # Check if IP address
    ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if re.match(ip_pattern, value):
        octets = value.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            return value
        raise click.BadParameter(f"Invalid IP address: {value}")
    
    # Check if domain
    domain_pattern = r'^[a-z0-9][-a-z0-9.]*\.[a-z]{2,}$'
    if re.match(domain_pattern, value, re.IGNORECASE):
        return value
    
    raise click.BadParameter(f"Invalid target format: {value}")



def _common_options(func):
    """Decorator to add common options to commands."""

    func = click.option("--timeout", default=600, type=click.IntRange(1, 3600), show_default=True, help="Max execution time (1-3600s)")(func)
    func = click.option("-v", "--verbose", is_flag=True, help="Enable debug logging")(func)
    func = click.option("--output", default="report.json", type=click.Path(), show_default=True, help="Output JSON file")(func)
    func = click.option("--target", required=True, callback=validate_target, help="Target URL/IP or domain")(func)
    return func


@click.group()
def cli() -> None:
    """X-Caliber Automation Framework"""
    pass


@cli.command()
@click.option("--rate-limit", default=10, type=click.IntRange(1, 100), help="Requests per second (1-100)")
@_common_options
def auto(target: str, output: str, verbose: bool, timeout: int, rate_limit: int) -> None:
    """Run full automation pipeline (recon -> scan -> exploit -> ctf -> report)"""
    click.echo(f"[AUTO] Starting automation for {target}")
    click.echo(f"[AUTO] Output: {output}, Timeout: {timeout}s, Rate: {rate_limit}rps")

    orch = AutomationOrchestrator()
    try:
        results = asyncio.run(orch.run_full_pipeline(target))

        # Write JSON output
        try:
            with open(output, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
        except Exception as e:
            click.echo(f"[AUTO] Failed to write output to {output}: {e}", err=True)
            raise click.Abort()

        # Print a brief summary
        phases = results.get("phases", {}) if isinstance(results, dict) else {}
        click.echo(f"[AUTO] Completed. Phases: {', '.join(phases.keys()) if phases else 'full_pipeline'}")
        click.echo(f"[AUTO] Results saved to {output}")
    except Exception as e:
        click.echo(f"[AUTO] Error during automation: {e}", err=True)
        raise click.Abort()


@cli.command()
@_common_options
def recon(target: str, output: str, verbose: bool, timeout: int) -> None:
    """Run reconnaissance only"""
    click.echo(f"[RECON] Reconnaissance for {target}")

    orch = AutomationOrchestrator()
    try:
        results = asyncio.run(orch.run_recon(target))

        try:
            with open(output, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
        except Exception as e:
            click.echo(f"[RECON] Failed to write output to {output}: {e}", err=True)
            raise click.Abort()

        # Human-readable summary
        subdomains = results.get("subdomains", []) if isinstance(results, dict) else []
        ports = results.get("ports", []) if isinstance(results, dict) else []
        click.echo(f"[RECON] Found {len(subdomains)} subdomains")
        click.echo(f"[RECON] Found {len(ports)} open ports")
        click.echo(f"[RECON] Results saved to {output}")
    except Exception as e:
        click.echo(f"[RECON] Error: {e}", err=True)
        raise click.Abort()


@cli.command()
@click.option("--severity", multiple=True, type=click.Choice(['critical', 'high', 'medium', 'low', 'info']), help="Filter by severity")
@_common_options
def scan(target: str, output: str, verbose: bool, timeout: int, severity: Tuple[str, ...]) -> None:
    """Run vulnerability scanning only"""
    click.echo(f"[SCAN] Scanning {target}")
    if severity:
        click.echo(f"[SCAN] Severity filter: {', '.join(severity)}")

    orch = AutomationOrchestrator()
    try:
        # Run recon first to supply recon_results for scan
        recon_results = asyncio.run(orch.run_recon(target))
        results = asyncio.run(orch.run_scan(target, recon_results))

        try:
            with open(output, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
        except Exception as e:
            click.echo(f"[SCAN] Failed to write output to {output}: {e}", err=True)
            raise click.Abort()

        vulns = results.get("vulnerabilities", []) if isinstance(results, dict) else []
        services = results.get("services", []) if isinstance(results, dict) else []
        click.echo(f"[SCAN] Found {len(vulns)} vulnerabilities")
        click.echo(f"[SCAN] Detected {len(services)} services")
        click.echo(f"[SCAN] Results saved to {output}")
    except Exception as e:
        click.echo(f"[SCAN] Error: {e}", err=True)
        raise click.Abort()


@cli.command()
@_common_options
@click.option("--exploit", is_flag=True, help="Enable exploit mode (REQUIRED for exploitation)")
@click.option("--allow-localhost", is_flag=True, help="Allow targeting localhost (use with caution)")
def exploit(target: str, output: str, verbose: bool, timeout: int, exploit: bool, allow_localhost: bool) -> None:
    """Run exploitation (requires --exploit flag for safety)"""
    if not exploit:
        # Safe default: do not perform exploitation, but exit cleanly
        click.echo("[EXPLOIT] Exploit flag not provided. Use --exploit to enable exploitation steps.")
        return
    
    # Check localhost - extract host from URL first
    host = target
    if '://' in target:
        # Extract host from URL (remove protocol, path)
        host = target.split('://')[1].split('/')[0]
        # Handle IPv6 brackets [::1] and port
        if host.startswith('['):
            host = host.split(']')[0][1:]  # Remove [ and ]
        else:
            host = host.split(':')[0]  # Remove port for IPv4
    
    if ('localhost' in host.lower() or host.startswith('127.') or host.startswith('::1') or host == '::1') and not allow_localhost:
        click.echo("[EXPLOIT] Localhost targeting requires --allow-localhost flag")
        raise click.Abort()
    
    click.echo(f"[EXPLOIT] Exploiting {target} (output={output})")

    orch = AutomationOrchestrator()
    try:
        # Get recon and scan results to feed exploit
        recon_results = asyncio.run(orch.run_recon(target))
        scan_results = asyncio.run(orch.run_scan(target, recon_results))
        results = asyncio.run(orch.run_exploit(target, scan_results))

        try:
            with open(output, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
        except Exception as e:
            click.echo(f"[EXPLOIT] Failed to write output to {output}: {e}", err=True)
            raise click.Abort()

        exploits = results.get("successful_exploits", []) if isinstance(results, dict) else []
        shells = results.get("shells", []) if isinstance(results, dict) else []
        click.echo(f"[EXPLOIT] Successful exploits: {len(exploits)}")
        click.echo(f"[EXPLOIT] Active shells: {len(shells)}")
        click.echo(f"[EXPLOIT] Results saved to {output}")
    except Exception as e:
        click.echo(f"[EXPLOIT] Error: {e}", err=True)
        raise click.Abort()


@cli.command()
@_common_options
def ctf(target: str, output: str, verbose: bool, timeout: int) -> None:
    """Run CTF-focused automation only"""
    click.echo(f"[CTF] Running CTF automation for {target}")

    orch = AutomationOrchestrator()
    try:
        results = asyncio.run(orch.run_ctf(target))

        try:
            with open(output, "w", encoding="utf-8") as fh:
                json.dump(results, fh, indent=2)
        except Exception as e:
            click.echo(f"[CTF] Failed to write output to {output}: {e}", err=True)
            raise click.Abort()

        flags = results.get("flags", []) if isinstance(results, dict) else []
        solved = results.get("challenges_solved", []) if isinstance(results, dict) else []
        click.echo(f"[CTF] Found {len(flags)} flags")
        click.echo(f"[CTF] Solved {len(solved)} challenges")
        click.echo(f"[CTF] Results saved to {output}")
    except Exception as e:
        click.echo(f"[CTF] Error: {e}", err=True)
        raise click.Abort()


if __name__ == "__main__":
    cli()
