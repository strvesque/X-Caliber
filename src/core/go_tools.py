"""Python wrappers for Go recon tools (subdomain, portscan, httpprobe).

Each wrapper runs the corresponding Go binary via subprocess, parses JSON
stdout, validates it using validators in src.core.ipc, and returns the parsed
dictionary. Errors are surfaced via custom exceptions.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
from typing import Any, Dict, List

from jsonschema import ValidationError

from src.core import ipc

logger = logging.getLogger("x_caliber.go_tools")


class GoToolError(Exception):
    """Base exception for Go tool errors."""


class GoToolNotFoundError(GoToolError):
    """Raised when Go binary not found."""


class GoToolTimeoutError(GoToolError):
    """Raised when Go tool exceeds timeout."""


class InvalidJSONError(GoToolError):
    """Raised when Go tool returns invalid JSON or schema mismatch."""


def _run_and_parse(cmd: List[str], timeout: int) -> Dict[str, Any]:
    logger.debug("Running command: %s", " ".join(cmd))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        logger.error("Command timed out: %s", e)
        raise GoToolTimeoutError(f"Tool exceeded timeout of {timeout}s")
    except FileNotFoundError:
        logger.error("Binary not found: %s", cmd[0] if cmd else "")
        raise GoToolNotFoundError(f"Binary not found: {cmd[0] if cmd else 'unknown'}")

    if result.returncode != 0:
        logger.error("Tool failed (rc=%s): %s", result.returncode, result.stderr.strip())
        raise GoToolError(f"Binary failed with exit code {result.returncode}: {result.stderr.strip()}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        logger.error("Invalid JSON from tool: %s", e)
        raise InvalidJSONError(f"Failed to parse JSON: {e}")

    return data


def run_subdomain_enum(
    target: str,
    binary_path: str = "./recon_go/xcal-subdomain.exe",
    timeout: int = 300,
) -> Dict[str, Any]:
    """Run Go subdomain enumerator and return parsed results.

    Args:
        target: Domain to enumerate (e.g., "example.com")
        binary_path: Path to xcal-subdomain binary
        timeout: Timeout in seconds (default 300)

    Returns:
        Dict matching subdomain IPC schema
    """
    if not os.path.isfile(binary_path):
        logger.error("Binary not found at path: %s", binary_path)
        raise GoToolNotFoundError(f"Binary not found: {binary_path}")

    cmd = [binary_path, "--target", target, "--json"]
    data = _run_and_parse(cmd, timeout)

    try:
        valid = ipc.validate_subdomain_output(data)
    except ValidationError as e:
        logger.error("Subdomain schema validation error: %s", e)
        raise InvalidJSONError(str(e))

    if not valid:
        logger.error("Subdomain output failed validation (boolean false): %s", data)
        raise InvalidJSONError("JSON does not match subdomain schema")

    return data


def run_port_scan(
    target: str,
    ports: str = "1-1000",
    binary_path: str = "./recon_go/xcal-portscan.exe",
    timeout: int = 300,
) -> Dict[str, Any]:
    """Run Go port scanner and return parsed results."""
    if not os.path.isfile(binary_path):
        logger.error("Binary not found at path: %s", binary_path)
        raise GoToolNotFoundError(f"Binary not found: {binary_path}")

    cmd = [binary_path, target, "--ports", ports, "--json"]
    data = _run_and_parse(cmd, timeout)

    try:
        valid = ipc.validate_port_scan_output(data)
    except ValidationError as e:
        logger.error("Port scan schema validation error: %s", e)
        raise InvalidJSONError(str(e))

    if not valid:
        logger.error("Port scan output failed validation (boolean false): %s", data)
        raise InvalidJSONError("JSON does not match port scan schema")

    return data


def run_http_probe(
    urls: List[str],
    workers: int = 50,
    binary_path: str = "./recon_go/xcal-httpprobe.exe",
    timeout: int = 300,
) -> Dict[str, Any]:
    """Run HTTP probe and return parsed results.

    The Go httpprobe accepts a comma-separated list of URLs via the --urls flag.
    """
    if not os.path.isfile(binary_path):
        logger.error("Binary not found at path: %s", binary_path)
        raise GoToolNotFoundError(f"Binary not found: {binary_path}")

    urls_arg = ",".join(urls)
    cmd = [binary_path, "--urls", urls_arg, "--workers", str(workers)]
    data = _run_and_parse(cmd, timeout)

    try:
        valid = ipc.validate_http_probe_output(data)
    except ValidationError as e:
        logger.error("HTTP probe schema validation error: %s", e)
        raise InvalidJSONError(str(e))

    if not valid:
        logger.error("HTTP probe output failed validation (boolean false): %s", data)
        raise InvalidJSONError("JSON does not match http probe schema")

    return data
