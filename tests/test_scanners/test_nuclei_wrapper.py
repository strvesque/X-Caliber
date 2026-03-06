"""Tests for NucleiScanner wrapper."""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

import pytest

from src.scanners.nuclei_wrapper import (
    NucleiNotFoundError,
    NucleiScanner,
    NucleiTimeoutError,
)


def _mock_nuclei_output() -> str:
    return "\n".join(
        [
            json.dumps(
                {
                    "template-id": "CVE-2021-44228",
                    "info": {
                        "name": "Log4j RCE",
                        "severity": "critical",
                        "description": "Test",
                        "tags": ["cve", "rce"],
                    },
                    "matched-at": "https://example.com/login",
                }
            ),
            "{invalid json}",
        ]
    )


def test_parse_output_handles_invalid_lines():
    scanner = NucleiScanner()
    results = scanner.parse_output(_mock_nuclei_output())
    assert len(results) == 1
    assert results[0]["template_id"] == "CVE-2021-44228"


@patch("subprocess.run")
def test_update_templates_success(mock_run: MagicMock) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    scanner = NucleiScanner()
    assert scanner.update_templates() is True


@patch("subprocess.run")
def test_update_templates_failure(mock_run: MagicMock) -> None:
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="failed")
    scanner = NucleiScanner()
    assert scanner.update_templates() is False


@patch("subprocess.run")
def test_update_templates_binary_missing(mock_run: MagicMock) -> None:
    mock_run.side_effect = FileNotFoundError
    scanner = NucleiScanner(binary_path="nuclei")
    with pytest.raises(NucleiNotFoundError):
        _ = scanner.update_templates()


@patch("subprocess.run")
def test_scan_success_parses_output(mock_run: MagicMock) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout=_mock_nuclei_output(), stderr="")
    scanner = NucleiScanner()
    result = scanner.scan("https://example.com")
    assert result["target"] == "https://example.com"
    vulnerabilities = cast(list[object], result["vulnerabilities"])
    assert len(vulnerabilities) == 1
    assert "scan_time" in result and isinstance(result["scan_time"], float)
    assert "timestamp" in result


@patch("subprocess.run")
def test_scan_includes_filters_and_templates(mock_run: MagicMock, tmp_path: Path) -> None:
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    scanner = NucleiScanner(templates_dir=str(templates_dir))
    _ = scanner.scan("https://example.com", severity=["critical", "high"], tags=["cve", "owasp"])

    cmd = cast(list[str], mock_run.call_args[0][0])
    assert "-severity" in cmd
    assert "critical,high" in cmd
    assert "-tags" in cmd
    assert "cve,owasp" in cmd
    assert "-t" in cmd
    assert str(templates_dir) in cmd


@patch("subprocess.run")
def test_scan_timeout(mock_run: MagicMock) -> None:
    mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nuclei"], timeout=1)
    scanner = NucleiScanner()
    with pytest.raises(NucleiTimeoutError):
        _ = scanner.scan("https://example.com", timeout=1)


@patch("subprocess.run")
def test_scan_binary_missing(mock_run: MagicMock) -> None:
    mock_run.side_effect = FileNotFoundError
    scanner = NucleiScanner(binary_path="nuclei")
    with pytest.raises(NucleiNotFoundError):
        _ = scanner.scan("https://example.com")


@patch("subprocess.run")
def test_scan_empty_results(mock_run: MagicMock) -> None:
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
    scanner = NucleiScanner()
    result = scanner.scan("https://example.com")
    assert result["vulnerabilities"] == []


def test_auto_update_templates_when_missing(tmp_path: Path) -> None:
    missing_dir = tmp_path / "missing-templates"
    scanner = NucleiScanner(templates_dir=str(missing_dir))

    with patch.object(scanner, "update_templates", return_value=True) as mock_update, patch(
        "subprocess.run"
    ) as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _ = scanner.scan("https://example.com")
        mock_update.assert_called_once()


def test_auto_update_templates_when_stale(tmp_path: Path) -> None:
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    stale_file = templates_dir / "template.yaml"
    _ = stale_file.write_text("test")
    old_time = time.time() - (9 * 24 * 60 * 60)
    _ = os.utime(templates_dir, (old_time, old_time))

    scanner = NucleiScanner(templates_dir=str(templates_dir))

    with patch.object(scanner, "update_templates", return_value=True) as mock_update, patch(
        "subprocess.run"
    ) as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        _ = scanner.scan("https://example.com")
        mock_update.assert_called_once()
