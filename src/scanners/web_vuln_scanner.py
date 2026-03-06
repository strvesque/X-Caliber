"""Custom Web Vulnerability Scanner with SQLi/XSS/CSRF detection."""
from __future__ import annotations

import asyncio
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger("x_caliber.web_vuln_scanner")


class WebVulnScannerError(Exception):
    """Base exception for web vulnerability scanner errors."""


class WebVulnScannerTimeoutError(WebVulnScannerError):
    """Raised when scan exceeds timeout."""


class WebVulnScanner:
    """Custom web vulnerability scanner detecting SQLi, XSS, and CSRF."""

    # SQL injection payloads
    SQLI_PAYLOADS = [
        "'",
        '"',
        "1' OR '1'='1",
        '1" OR "1"="1',
        "1' OR '1'='1' --",
        "1' OR '1'='1' /*",
    ]

    # SQL error patterns
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ORA-\d{5}",
        r"Oracle error",
        r"DB2 SQL error",
        r"SQLSTATE\[",
        r"sqlite3\.",
        r"SQLite\/JDBCDriver",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Syntax error.*SQL",
        r"syntax error.*near",
        r"Microsoft SQL Server.*Driver",
        r"SQL Server.*\[Microsoft\]",
    ]

    # XSS test payload
    XSS_PAYLOAD = "<script>alert(xss)</script>"

    def __init__(self, timeout: float = 10.0, rate_limit_delay: float = 1.0) -> None:
        """Initialize web vulnerability scanner.

        Args:
            timeout: Request timeout in seconds (default 10.0)
            rate_limit_delay: Delay between requests in seconds (default 1.0)
        """
        self.timeout = timeout
        self.rate_limit_delay = rate_limit_delay

    async def scan_sqli(
        self, url: str, params: Dict[str, str] | None = None
    ) -> List[Dict[str, Any]]:
        """Scan for SQL injection vulnerabilities.

        Tests multiple SQL injection payloads and checks for database error
        patterns in responses.

        Args:
            url: Target URL to test
            params: URL parameters to inject payloads into

        Returns:
            List of detected SQL injection vulnerabilities

        Raises:
            WebVulnScannerTimeoutError: If request times out
        """
        vulnerabilities: List[Dict[str, Any]] = []
        if params is None:
            params = {}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for param_name, param_value in params.items():
                for payload in self.SQLI_PAYLOADS:
                    # Inject payload into parameter
                    test_params = params.copy()
                    test_params[param_name] = payload

                    try:
                        response = await client.get(url, params=test_params)
                    except asyncio.TimeoutError as exc:
                        raise WebVulnScannerTimeoutError(
                            f"Request timed out after {self.timeout}s"
                        ) from exc

                    # Check for SQL error patterns
                    for pattern in self.SQL_ERROR_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append(
                                {
                                    "type": "sqli",
                                    "severity": "high",
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": self._extract_evidence(
                                        response.text, pattern
                                    ),
                                    "url": str(response.url),
                                }
                            )
                            break

                    # Rate limiting
                    await asyncio.sleep(self.rate_limit_delay)

        return vulnerabilities

    async def scan_xss(
        self, url: str, params: Dict[str, str] | None = None
    ) -> List[Dict[str, Any]]:
        """Scan for reflected XSS vulnerabilities.

        Tests if XSS payload is reflected unescaped in HTML response.

        Args:
            url: Target URL to test
            params: URL parameters to inject payloads into

        Returns:
            List of detected XSS vulnerabilities

        Raises:
            WebVulnScannerTimeoutError: If request times out
        """
        vulnerabilities: List[Dict[str, Any]] = []
        if params is None:
            params = {}

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for param_name, param_value in params.items():
                # Inject XSS payload
                test_params = params.copy()
                test_params[param_name] = self.XSS_PAYLOAD

                try:
                    response = await client.get(url, params=test_params)
                except asyncio.TimeoutError as exc:
                    raise WebVulnScannerTimeoutError(
                        f"Request timed out after {self.timeout}s"
                    ) from exc

                # Check if payload reflected unescaped in HTML response
                content_type = response.headers.get("content-type", "")
                if "text/html" in content_type.lower():
                    if self.XSS_PAYLOAD in response.text:
                        vulnerabilities.append(
                            {
                                "type": "xss",
                                "severity": "high",
                                "parameter": param_name,
                                "payload": self.XSS_PAYLOAD,
                                "evidence": "Payload reflected unescaped in response",
                                "url": str(response.url),
                            }
                        )

                # Rate limiting
                await asyncio.sleep(self.rate_limit_delay)

        return vulnerabilities

    async def scan_csrf(self, url: str) -> Dict[str, Any]:
        """Scan for missing CSRF protection.

        Checks if POST forms contain CSRF tokens.

        Args:
            url: Target URL to test

        Returns:
            Dictionary with CSRF vulnerability status

        Raises:
            WebVulnScannerTimeoutError: If request times out
        """
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(url)
            except asyncio.TimeoutError as exc:
                raise WebVulnScannerTimeoutError(
                    f"Request timed out after {self.timeout}s"
                ) from exc

        # Parse HTML and find forms
        soup = BeautifulSoup(response.text, "html.parser")
        post_forms = soup.find_all("form", method="post") + soup.find_all("form", method="POST")

        forms_without_csrf: List[Dict[str, str]] = []
        csrf_pattern = re.compile(r"csrf|token", re.IGNORECASE)

        for form in post_forms:
            # Check if form has CSRF token input
            has_csrf = False
            for input_tag in form.find_all("input"):
                input_name = str(input_tag.get("name", ""))
                if csrf_pattern.search(input_name):
                    has_csrf = True
                    break

            if not has_csrf:
                forms_without_csrf.append(
                    {
                        "action": str(form.get("action", "")),
                        "method": str(form.get("method", "")),
                    }
                )

        vulnerable = len(forms_without_csrf) > 0

        return {
            "type": "csrf",
            "vulnerable": vulnerable,
            "severity": "medium" if vulnerable else "info",
            "forms_without_csrf": forms_without_csrf,
            "total_post_forms": len(post_forms),
        }

    async def scan_all(self, url: str) -> Dict[str, Any]:
        """Run all vulnerability scans on a target URL.

        Executes SQLi, XSS, and CSRF scans and returns comprehensive results.

        Args:
            url: Target URL to scan

        Returns:
            Dictionary with all scan results including vulnerabilities and metadata
        """
        start_time = time.time()

        # Extract base URL and common parameters for testing
        test_params = {"id": "1", "page": "1", "search": "test"}

        # Run all scans
        sqli_results = await self.scan_sqli(url, test_params)
        await asyncio.sleep(self.rate_limit_delay)

        xss_results = await self.scan_xss(url, test_params)
        await asyncio.sleep(self.rate_limit_delay)

        csrf_result = await self.scan_csrf(url)

        scan_time = time.time() - start_time
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        return {
            "url": url,
            "vulnerabilities": {
                "sqli": sqli_results,
                "xss": xss_results,
                "csrf": csrf_result,
            },
            "scan_time": scan_time,
            "timestamp": timestamp,
        }

    def _extract_evidence(self, text: str, pattern: str) -> str:
        """Extract evidence snippet from response text.

        Args:
            text: Response text to search
            pattern: Regex pattern that matched

        Returns:
            Evidence snippet (max 200 chars)
        """
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 50)
            snippet = text[start:end].strip()
            return snippet[:200]
        return ""
