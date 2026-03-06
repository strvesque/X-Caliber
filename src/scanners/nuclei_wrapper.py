"""Nuclei scanner wrapper with template management."""
from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from typing import cast

logger = logging.getLogger("x_caliber.nuclei")

DEFAULT_TEMPLATE_STALE_DAYS = 7


class NucleiError(Exception):
    """Base exception for Nuclei wrapper errors."""


class NucleiNotFoundError(NucleiError):
    """Raised when nuclei binary is not found."""


class NucleiTimeoutError(NucleiError):
    """Raised when nuclei scan exceeds timeout."""


class NucleiScanner:
    """Wrapper around the nuclei CLI with template management."""

    def __init__(self, binary_path: str = "nuclei", templates_dir: str | None = None) -> None:
        self.binary_path: str = binary_path
        self.templates_dir: str | None = templates_dir

    def update_templates(self) -> bool:
        """Update nuclei templates. Returns True on success."""
        cmd = [self.binary_path, "-update-templates"]
        logger.debug("Updating nuclei templates: %s", " ".join(cmd))

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except FileNotFoundError:
            raise NucleiNotFoundError(
                (
                    "nuclei binary not found. Install: "
                    "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
                )
            )
        except subprocess.TimeoutExpired:
            logger.warning("Template update timed out")
            return False

        if result.returncode != 0:
            logger.warning("Template update failed: %s", result.stderr.strip())
            return False

        return True

    def _templates_need_update(self) -> bool:
        if not self.templates_dir:
            return False
        if not os.path.isdir(self.templates_dir):
            return True

        try:
            mtime = os.path.getmtime(self.templates_dir)
        except OSError:
            return True

        age_seconds = time.time() - mtime
        return age_seconds > (DEFAULT_TEMPLATE_STALE_DAYS * 24 * 60 * 60)

    def scan(
        self,
        target: str,
        severity: list[str] | None = None,
        tags: list[str] | None = None,
        timeout: int = 600,
    ) -> dict[str, object]:
        """Run nuclei scan on a target."""
        start = time.time()

        if self._templates_need_update():
            if not self.update_templates():
                logger.warning("Continuing with existing templates after update failure")

        cmd = [self.binary_path, "-target", target, "-json"]
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        if self.templates_dir:
            cmd.extend(["-t", self.templates_dir])

        logger.debug("Running nuclei command: %s", " ".join(cmd))

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise NucleiTimeoutError(f"nuclei scan timed out after {timeout}s") from exc
        except FileNotFoundError as exc:
            raise NucleiNotFoundError(
                (
                    "nuclei binary not found. Install: "
                    "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
                )
            ) from exc

        if result.returncode != 0:
            logger.warning("nuclei exited non-zero: %s", result.stderr.strip())

        vulnerabilities = self.parse_output(result.stdout)
        scan_time = time.time() - start
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return {
            "target": target,
            "vulnerabilities": vulnerabilities,
            "scan_time": scan_time,
            "timestamp": timestamp,
        }

    def parse_output(self, json_lines: str) -> list[dict[str, object]]:
        """Parse newline-delimited nuclei JSON output."""
        vulnerabilities: list[dict[str, object]] = []
        if not json_lines:
            return vulnerabilities

        for line in json_lines.strip().split("\n"):
            if not line:
                continue
            try:
                vuln = cast(dict[str, object], json.loads(line))
            except json.JSONDecodeError as exc:
                logger.error("Invalid JSON line from nuclei: %s", exc)
                continue

            vulnerabilities.append(
                {
                    "template_id": vuln.get("template-id"),
                    "name": cast(dict[str, object], vuln.get("info", {})).get("name"),
                    "severity": cast(dict[str, object], vuln.get("info", {})).get(
                        "severity"
                    ),
                    "matched_at": vuln.get("matched-at"),
                    "description": cast(dict[str, object], vuln.get("info", {})).get(
                        "description"
                    ),
                    "tags": cast(dict[str, object], vuln.get("info", {})).get(
                        "tags", []
                    ),
                }
            )

        return vulnerabilities
