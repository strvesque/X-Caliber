"""JSON report generator for automation pipeline results."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Mapping
from typing import cast

from src.scanners.vuln_classifier import VulnClassifier

logger = logging.getLogger("x_caliber.report.json_generator")


class JSONReportGenerator:
    """Generate structured JSON reports from pipeline results.

    Consumes output from AutomationOrchestrator.run_full_pipeline() and
    produces a comprehensive JSON report with metadata, phase results,
    vulnerabilities, and summary statistics.

    Example:
        generator = JSONReportGenerator()
        pipeline_results = await orchestrator.run_full_pipeline("example.com")
        generator.generate(pipeline_results, "report.json")
    """

    VERSION: str = "x-caliber-automation-0.1.0"

    def __init__(self) -> None:
        """Initialize report generator."""
        logger.info("JSONReportGenerator initialized")
        self._classifier: VulnClassifier = VulnClassifier()

    def generate(self, pipeline_results: object, output_path: str) -> None:
        """Generate JSON report from pipeline results.

        Args:
            pipeline_results: Output from run_full_pipeline()
            output_path: Path to write JSON report

        Raises:
            IOError: If unable to write report file
            ValueError: If pipeline_results missing required keys
        """
        if not isinstance(pipeline_results, Mapping):
            raise ValueError("pipeline_results must be a dictionary")
        pipeline_results = cast(Mapping[str, object], pipeline_results)

        logger.info("Generating JSON report: %s", output_path)

        metadata = self._build_metadata(pipeline_results)
        phases = self._build_phases(pipeline_results)
        vulnerabilities = self._extract_vulnerabilities(pipeline_results)
        errors = self._extract_errors(pipeline_results)
        summary = self._build_summary(vulnerabilities, phases)

        report: dict[str, object] = {
            "metadata": metadata,
            "phases": phases,
            "vulnerabilities": vulnerabilities,
            "summary": summary,
            "errors": errors,
        }

        self._write_json(cast(Mapping[str, object], report), output_path)
        logger.info("Report generated: %s", output_path)

    def _build_metadata(self, results: Mapping[str, object]) -> dict[str, object]:
        """Build metadata section."""
        state = self._ensure_dict(results.get("state"))
        timing = self._ensure_dict(state.get("timing"))

        execution_time = 0.0
        execution_time = sum(
            value for value in timing.values() if isinstance(value, (int, float))
        )

        return {
            "target": self._extract_target(results),
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "execution_time_seconds": round(execution_time, 2),
            "phases_completed": self._ensure_list(state.get("completed_phases")),
            "phases_failed": self._get_failed_phases(results),
            "tool_version": self.VERSION,
        }

    def _build_phases(
        self, results: Mapping[str, object]
    ) -> dict[str, dict[str, object]]:
        """Build phases section with status and results."""
        phases: dict[str, dict[str, object]] = {}
        state = self._ensure_dict(results.get("state"))
        timing = self._ensure_dict(state.get("timing"))

        for phase_name in ["recon", "scan", "exploit", "ctf"]:
            phase_data = self._ensure_dict(results.get(phase_name))
            duration = timing.get(phase_name, 0.0)

            phases[phase_name] = {
                "status": self._get_str(phase_data, "status", "unknown"),
                "duration_seconds": round(duration, 2)
                if isinstance(duration, (int, float))
                else 0.0,
                "results": self._extract_phase_results(phase_name, phase_data),
            }

            if "error" in phase_data:
                phases[phase_name]["error"] = phase_data.get("error")

        return phases

    def _extract_phase_results(
        self, phase: str, data: dict[str, object]
    ) -> dict[str, object]:
        """Extract relevant results for each phase."""
        if phase == "recon":
            return {
                "subdomains": self._ensure_list(data.get("subdomains")),
                "open_ports": self._ensure_list(data.get("ports")),
                "http_services": self._ensure_list(data.get("http_services")),
            }
        if phase == "scan":
            return {
                "vulnerabilities_found": len(
                    self._ensure_list(data.get("vulnerabilities"))
                ),
                "targets_scanned": len(self._ensure_list(data.get("services"))),
            }
        if phase == "exploit":
            return {
                "successful_exploits": len(
                    self._ensure_list(data.get("successful_exploits"))
                ),
                "shells": len(self._ensure_list(data.get("shells"))),
            }
        if phase == "ctf":
            return {
                "flags_found": len(self._ensure_list(data.get("flags"))),
                "challenges_solved": len(
                    self._ensure_list(data.get("challenges_solved"))
                ),
            }
        return {}

    def _extract_vulnerabilities(
        self, results: Mapping[str, object]
    ) -> list[dict[str, object]]:
        """Extract and normalize all vulnerabilities from scan phase."""
        vulnerabilities: list[dict[str, object]] = []
        scan_data = self._ensure_dict(results.get("scan"))

        raw_vulns = self._ensure_list(scan_data.get("vulnerabilities"))

        for idx, vuln in enumerate(raw_vulns, 1):
            if not isinstance(vuln, dict):
                continue

            vuln_dict = cast(dict[str, object], vuln)

            vuln_type = self._get_str(vuln_dict, "type", "unknown")
            severity = self._classify_severity(vuln_type, vuln_dict)

            normalized: dict[str, object] = {
                "id": f"vuln-{idx:03d}",
                "type": vuln_type,
                "severity": severity,
                "target": self._get_str(
                    vuln_dict,
                    "target",
                    self._get_str(scan_data, "target", "unknown"),
                ),
                "phase": "scan",
                "description": self._get_str(
                    vuln_dict,
                    "message",
                    self._get_str(vuln_dict, "description", "No description"),
                ),
            }

            if "cvss_score" in vuln_dict:
                normalized["cvss_score"] = vuln_dict.get("cvss_score")
            if "cwe_id" in vuln_dict or "cwe" in vuln_dict:
                normalized["cwe_id"] = vuln_dict.get("cwe_id") or vuln_dict.get("cwe")

            vulnerabilities.append(normalized)

        return vulnerabilities

    def _build_summary(
        self,
        vulnerabilities: list[dict[str, object]],
        phases: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        """Build summary statistics."""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "info")
            if severity in by_severity:
                by_severity[cast(str, severity)] += 1

        by_phase: dict[str, int] = {}
        for phase_name, phase_data in phases.items():
            if phase_name == "scan":
                results = self._ensure_dict(phase_data.get("results"))
                by_phase[phase_name] = cast(int, results.get("vulnerabilities_found", 0))
            else:
                by_phase[phase_name] = 0

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "by_severity": by_severity,
            "by_phase": by_phase,
        }

    def _extract_errors(self, results: Mapping[str, object]) -> list[dict[str, object]]:
        """Extract errors from state."""
        state = self._ensure_dict(results.get("state"))
        errors: list[dict[str, object]] = []

        for error in self._ensure_list(state.get("errors")):
            if not isinstance(error, dict):
                continue
            error_dict = cast(dict[str, object], error)
            errors.append(
                {
                    "phase": self._get_str(error_dict, "phase", "unknown"),
                    "error": self._get_str(error_dict, "error", "Unknown error"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )

        return errors

    def _extract_target(self, results: Mapping[str, object]) -> str:
        """Extract target from results."""
        for phase in ["recon", "scan", "exploit", "ctf"]:
            if phase in results and isinstance(results[phase], dict):
                phase_data = cast(dict[str, object], results[phase])
                if "target" in phase_data:
                    return self._get_str(phase_data, "target", "unknown")
        return "unknown"

    def _get_failed_phases(self, results: Mapping[str, object]) -> list[str]:
        """Get list of failed phases."""
        failed: list[str] = []
        for phase in ["recon", "scan", "exploit", "ctf"]:
            if phase in results and isinstance(results[phase], dict):
                phase_data = cast(dict[str, object], results[phase])
                if phase_data.get("status") == "failed":
                    failed.append(phase)
        return failed

    def _classify_severity(self, vuln_type: str, vuln: dict[str, object]) -> str:
        """Classify severity using VulnClassifier with graceful fallback."""
        if "severity" in vuln and isinstance(vuln.get("severity"), str):
            return cast(str, vuln.get("severity"))

        details: dict[str, object] = {
            "exploit_available": vuln.get("exploit_available"),
        }
        cwe_value = vuln.get("cwe_id") or vuln.get("cwe")
        if cwe_value:
            details["cwe"] = cwe_value
        return self._classifier.classify(vuln_type, details)

    def _write_json(self, data: Mapping[str, object], path: str) -> None:
        """Write JSON to file with pretty formatting."""
        output_file = Path(path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            with output_file.open("w", encoding="utf-8") as file_handle:
                json.dump(data, file_handle, indent=2, ensure_ascii=False)
        except OSError as exc:
            raise IOError(f"Unable to write JSON report to {path}") from exc

    @staticmethod
    def _ensure_dict(value: object) -> dict[str, object]:
        if isinstance(value, dict):
            return cast(dict[str, object], value)
        return {}

    @staticmethod
    def _ensure_list(value: object) -> list[object]:
        if isinstance(value, list):
            return list(cast(list[object], value))
        return []

    @staticmethod
    def _get_str(data: dict[str, object], key: str, default: str) -> str:
        value = data.get(key)
        return value if isinstance(value, str) else default
