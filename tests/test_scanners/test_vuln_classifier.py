"""Tests for VulnClassifier."""
import pytest
from src.scanners.vuln_classifier import VulnClassifier


class TestVulnClassifierBasic:
    def test_classify_sql_injection_is_critical(self):
        classifier = VulnClassifier()
        assert classifier.classify("sql_injection") == "critical"

    def test_classify_xss_reflected_is_high(self):
        classifier = VulnClassifier()
        assert classifier.classify("xss_reflected") == "high"

    def test_classify_csrf_is_medium(self):
        classifier = VulnClassifier()
        assert classifier.classify("csrf") == "medium"

    def test_classify_info_disclosure_is_low(self):
        classifier = VulnClassifier()
        assert classifier.classify("info_disclosure") == "low"

    def test_classify_unknown_type_defaults_to_info(self):
        classifier = VulnClassifier()
        assert classifier.classify("unknown_vuln") == "info"


class TestCWEMapping:
    def test_cwe_89_overrides_to_critical(self):
        classifier = VulnClassifier()
        result = classifier.classify("weak_csp", {"cwe": "CWE-89"})
        assert result == "critical"

    def test_cwe_79_is_high(self):
        classifier = VulnClassifier()
        assert classifier.get_severity_from_cwe("CWE-79") == "high"

    def test_cwe_352_is_medium(self):
        classifier = VulnClassifier()
        assert classifier.get_severity_from_cwe("CWE-352") == "medium"

    def test_cwe_200_is_low(self):
        classifier = VulnClassifier()
        assert classifier.get_severity_from_cwe("CWE-200") == "low"

    def test_unknown_cwe_defaults_to_low(self):
        classifier = VulnClassifier()
        assert classifier.get_severity_from_cwe("CWE-999") == "low"


class TestExploitEscalation:
    def test_exploit_available_escalates_low_to_medium(self):
        classifier = VulnClassifier()
        result = classifier.classify("info_disclosure", {"exploit_available": True})
        assert result == "medium"

    def test_exploit_available_escalates_medium_to_high(self):
        classifier = VulnClassifier()
        result = classifier.classify("csrf", {"exploit_available": True})
        assert result == "high"

    def test_exploit_available_escalates_high_to_critical(self):
        classifier = VulnClassifier()
        result = classifier.classify("xss_reflected", {"exploit_available": True})
        assert result == "critical"

    def test_exploit_available_caps_at_critical(self):
        classifier = VulnClassifier()
        result = classifier.classify("sql_injection", {"exploit_available": True})
        assert result == "critical"


class TestEdgeCases:
    def test_classify_with_none_details(self):
        classifier = VulnClassifier()
        assert classifier.classify("sql_injection", None) == "critical"

    def test_classify_with_empty_details(self):
        classifier = VulnClassifier()
        assert classifier.classify("sql_injection", {}) == "critical"

    def test_classify_case_insensitive(self):
        classifier = VulnClassifier()
        assert classifier.classify("SQL_INJECTION") == "critical"
        assert classifier.classify("Sql_Injection") == "critical"

    def test_cwe_none_returns_low(self):
        classifier = VulnClassifier()
        assert classifier.get_severity_from_cwe(None) == "low"

    def test_escalate_info_to_low(self):
        classifier = VulnClassifier()
        assert classifier._escalate("info") == "low"

    def test_escalate_unknown_severity_returns_unchanged(self):
        classifier = VulnClassifier()
        assert classifier._escalate("unknown") == "unknown"
