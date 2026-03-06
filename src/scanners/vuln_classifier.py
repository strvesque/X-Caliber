from typing import Dict, Any, Optional


class VulnClassifier:
    """Classifier for mapping vulnerability types and CWEs to severities.

    Behavior:
    - Uses SEVERITY_MAP to map string vulnerability types to severities.
    - If details contain a 'cwe' key, uses CWE_MAP to override the base severity.
    - If details indicate an exploit is available (details['exploit_available'] truthy),
      escalate the final severity by one level (up to critical).
    """

    SEVERITY_MAP = {
        "sql_injection": "critical",
        "rce": "critical",
        "xss_stored": "critical",
        "xss_reflected": "high",
        "csrf": "medium",
        "missing_hsts": "medium",
        "weak_csp": "low",
        "info_disclosure": "low",
    }

    CWE_MAP = {
        "CWE-89": "critical",  # SQLi
        "CWE-79": "high",      # XSS
        "CWE-352": "medium",   # CSRF
        "CWE-200": "low",      # Info Disclosure
    }

    def classify(self, vuln_type: str, details: Optional[Dict[str, Any]] = None) -> str:
        """Return a severity string for a vulnerability.

        Args:
            vuln_type: canonical vulnerability type string (case-insensitive)
            details: optional details dict. Known keys:
                - cwe: string CWE id (e.g. 'CWE-89') that can override severity
                - exploit_available: truthy if exploit exists (escalates severity)

        Returns:
            severity name: one of 'info', 'low', 'medium', 'high', 'critical'
        """
        details = details or {}

        # Normalize vuln_type to lower-case for lookup
        key = (vuln_type or "").lower()
        severity = self.SEVERITY_MAP.get(key, "info")

        # Override with CWE if present
        if "cwe" in details:
            # details['cwe'] might be None; get_severity_from_cwe will handle unknowns
            cwe_severity = self.get_severity_from_cwe(details.get("cwe"))
            if cwe_severity:
                severity = cwe_severity

        # Escalate if exploit available
        if details.get("exploit_available"):
            severity = self._escalate(severity)

        return severity

    def get_severity_from_cwe(self, cwe_id: Optional[str]) -> str:
        """Map a CWE id to a severity.

        If cwe_id is not found or falsy, return 'low' as a sensible default.
        """
        if not cwe_id:
            return "low"
        return self.CWE_MAP.get(cwe_id, "low")

    def _escalate(self, severity: str) -> str:
        """Escalate severity by one step, maxing out at 'critical'."""
        escalation = {
            "info": "low",
            "low": "medium",
            "medium": "high",
            "high": "critical",
            "critical": "critical",
        }
        return escalation.get(severity, severity)
