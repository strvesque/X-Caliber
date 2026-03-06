"""Click-based automation CLI for X-Caliber with validation.

Enhanced CLI with URL validation, rate limiting flags, and proper error handling.
"""
# pyright: reportMissingImports=false, reportFunctionMemberAccess=false
from __future__ import annotations

import click  # type: ignore
import re
from typing import Optional


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


@cli.command()
@_common_options
def recon(target: str, output: str, verbose: bool, timeout: int) -> None:
    """Run reconnaissance only"""
    click.echo(f"[RECON] Reconnaissance for {target}")


@cli.command()
@click.option("--severity", multiple=True, type=click.Choice(['critical', 'high', 'medium', 'low', 'info']), help="Filter by severity")
@_common_options
def scan(target: str, output: str, verbose: bool, timeout: int, severity: tuple) -> None:
    """Run vulnerability scanning only"""
    click.echo(f"[SCAN] Scanning {target}")
    if severity:
        click.echo(f"[SCAN] Severity filter: {', '.join(severity)}")


@cli.command()
@_common_options
@click.option("--exploit", is_flag=True, help="Enable exploit mode (REQUIRED for exploitation)")
@click.option("--allow-localhost", is_flag=True, help="Allow targeting localhost (use with caution)")
def exploit(target: str, output: str, verbose: bool, timeout: int, exploit: bool, allow_localhost: bool) -> None:
    """Run exploitation (requires --exploit flag for safety)"""
    if not exploit:
        click.echo("[EXPLOIT] --exploit flag required. Aborting for safety.")
        raise click.Abort()
    
    # Check localhost
    if 'localhost' in target.lower() or target.startswith('127.') and not allow_localhost:
        click.echo("[EXPLOIT] Localhost targeting requires --allow-localhost flag")
        raise click.Abort()
    
    click.echo(f"[EXPLOIT] Exploiting {target} (output={output})")


@cli.command()
@_common_options
def ctf(target: str, output: str, verbose: bool, timeout: int) -> None:
    """Run CTF-focused automation only"""
    click.echo(f"[CTF] Running CTF automation for {target}")


if __name__ == "__main__":
    cli()
