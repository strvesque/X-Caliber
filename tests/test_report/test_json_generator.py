"""Tests for JSON report generator."""

import json
from pathlib import Path
from typing import cast

import pytest

from src.report.json_generator import JSONReportGenerator


@pytest.fixture
def sample_pipeline_results() -> dict[str, object]:
    """Sample pipeline results for testing."""
    return {
        "recon": {
            "target": "example.com",
            "subdomains": ["sub1.example.com", "sub2.example.com"],
            "ports": [{"port": 80, "service": "http"}],
            "http_services": [{"url": "http://sub1.example.com", "status": 200}],
            "status": "success",
        },
        "scan": {
            "target": "example.com",
            "vulnerabilities": [
                {
                    "type": "sql_injection",
                    "severity": "critical",
                    "target": "http://example.com",
                    "message": "SQL injection",
                },
                {
                    "type": "xss_reflected",
                    "target": "http://example.com",
                    "description": "XSS found",
                },
            ],
            "services": [{"url": "http://example.com"}],
            "status": "success",
        },
        "exploit": {
            "target": "example.com",
            "status": "placeholder",
            "successful_exploits": [],
            "shells": [],
        },
        "ctf": {
            "target": "example.com",
            "flags": ["flag{test123}"],
            "challenges_solved": [{"type": "crypto"}],
            "status": "success",
        },
        "state": {
            "completed_phases": ["recon", "scan", "ctf"],
            "errors": [],
            "timing": {"recon": 10.5, "scan": 20.3, "exploit": 0.1, "ctf": 5.2},
        },
    }


class TestJSONReportGenerator:
    """Test JSONReportGenerator class."""

    @staticmethod
    def _as_dict(value: object) -> dict[str, object]:
        assert isinstance(value, dict)
        return cast(dict[str, object], value)

    @staticmethod
    def _as_list(value: object) -> list[object]:
        assert isinstance(value, list)
        return cast(list[object], value)

    def test_generator_instantiation(self):
        """Test generator can be instantiated."""
        generator = JSONReportGenerator()
        assert generator is not None
        assert generator.VERSION == "x-caliber-automation-0.1.0"

    def test_generate_creates_file(
        self, sample_pipeline_results: object, tmp_path: Path
    ) -> None:
        """Test generate() creates JSON file."""
        generator = JSONReportGenerator()
        output_path = tmp_path / "report.json"

        generator.generate(sample_pipeline_results, str(output_path))

        assert output_path.exists()
        assert output_path.stat().st_size > 0

    def test_report_structure(
        self, sample_pipeline_results: object, tmp_path: Path
    ) -> None:
        """Test generated report has correct structure."""
        generator = JSONReportGenerator()
        output_path = tmp_path / "report.json"

        generator.generate(sample_pipeline_results, str(output_path))

        with output_path.open(encoding="utf-8") as file_handle:
            report = cast(object, json.load(file_handle))
        report = self._as_dict(report)

        assert "metadata" in report
        assert "phases" in report
        assert "vulnerabilities" in report
        assert "summary" in report
        assert "errors" in report

    def test_metadata_section(
        self, sample_pipeline_results: object, tmp_path: Path
    ) -> None:
        """Test metadata section has correct fields."""
        generator = JSONReportGenerator()
        output_path = tmp_path / "report.json"

        generator.generate(sample_pipeline_results, str(output_path))

        with output_path.open(encoding="utf-8") as file_handle:
            report = cast(object, json.load(file_handle))
        report = self._as_dict(report)

        metadata = self._as_dict(report["metadata"])
        assert metadata["target"] == "example.com"
        assert "scan_date" in metadata
        assert metadata["execution_time_seconds"] == 36.1
        assert metadata["phases_completed"] == ["recon", "scan", "ctf"]
        assert metadata["tool_version"] == "x-caliber-automation-0.1.0"

    def test_vulnerabilities_extraction(
        self, sample_pipeline_results: object, tmp_path: Path
    ) -> None:
        """Test vulnerabilities are extracted correctly."""
        generator = JSONReportGenerator()
        output_path = tmp_path / "report.json"

        generator.generate(sample_pipeline_results, str(output_path))

        with output_path.open(encoding="utf-8") as file_handle:
            report = cast(object, json.load(file_handle))
        report = self._as_dict(report)

        vulns = cast(list[dict[str, object]], report["vulnerabilities"])
        assert len(vulns) == 2
        assert vulns[0]["id"] == "vuln-001"
        assert vulns[0]["type"] == "sql_injection"
        assert vulns[0]["severity"] == "critical"
        assert vulns[1]["id"] == "vuln-002"
        assert vulns[1]["type"] == "xss_reflected"
        assert vulns[1]["severity"] == "high"

    def test_summary_statistics(
        self, sample_pipeline_results: object, tmp_path: Path
    ) -> None:
        """Test summary section calculates correctly."""
        generator = JSONReportGenerator()
        output_path = tmp_path / "report.json"

        generator.generate(sample_pipeline_results, str(output_path))

        with output_path.open(encoding="utf-8") as file_handle:
            report = cast(object, json.load(file_handle))
        report = self._as_dict(report)

        summary = self._as_dict(report["summary"])
        assert summary["total_vulnerabilities"] == 2
        by_severity = self._as_dict(summary["by_severity"])
        by_phase = self._as_dict(summary["by_phase"])
        assert by_severity["critical"] == 1
        assert by_severity["high"] == 1
        assert by_phase["scan"] == 2

    def test_phases_section(
        self, sample_pipeline_results: object, tmp_path: Path
    ) -> None:
        """Test phases section has all phases."""
        generator = JSONReportGenerator()
        output_path = tmp_path / "report.json"

        generator.generate(sample_pipeline_results, str(output_path))

        with output_path.open(encoding="utf-8") as file_handle:
            report = cast(object, json.load(file_handle))
        report = self._as_dict(report)

        phases = self._as_dict(report["phases"])
        assert "recon" in phases
        assert "scan" in phases
        assert "exploit" in phases
        assert "ctf" in phases

        recon = self._as_dict(phases["recon"])
        recon_results = self._as_dict(recon["results"])
        assert recon["status"] == "success"
        assert recon["duration_seconds"] == 10.5
        assert len(self._as_list(recon_results["subdomains"])) == 2

    def test_error_handling_missing_keys(self, tmp_path: Path) -> None:
        """Test graceful handling of missing keys."""
        generator = JSONReportGenerator()
        output_path = tmp_path / "report.json"

        minimal_results: dict[str, object] = {
            "state": {"completed_phases": [], "errors": [], "timing": {}}
        }

        generator.generate(minimal_results, str(output_path))

        assert output_path.exists()
        with output_path.open(encoding="utf-8") as file_handle:
            report = cast(object, json.load(file_handle))
        report = self._as_dict(report)
        summary = self._as_dict(report["summary"])
        metadata = self._as_dict(report["metadata"])
        assert summary["total_vulnerabilities"] == 0
        assert metadata["phases_failed"] == []

    def test_json_formatting(
        self, sample_pipeline_results: object, tmp_path: Path
    ) -> None:
        """Test JSON is pretty-printed."""
        generator = JSONReportGenerator()
        output_path = tmp_path / "report.json"

        generator.generate(sample_pipeline_results, str(output_path))

        content = output_path.read_text(encoding="utf-8")

        assert "  " in content
        assert "\n" in content
