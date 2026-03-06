import httpx
from typing import Dict, Any
from datetime import datetime, timezone


class SecurityHeadersAnalyzer:
    """Analyze common security-related HTTP headers.

    The analyzer performs a HEAD request to the provided URL and inspects
    headers for several security controls: Content-Security-Policy (CSP),
    Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options
    and X-XSS-Protection. It returns a dict containing the original headers,
    a list of issues found and a simple numeric score.
    """

    async def analyze(self, url: str) -> Dict[str, Any]:
        # Use a short timeout and follow redirects to the final host
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.head(url, follow_redirects=True)

        headers = {k.lower(): v for k, v in response.headers.items()}
        issues = []
        score = 100

        # Check CSP
        if "content-security-policy" not in headers:
            issues.append({
                "header": "CSP",
                "severity": "critical",
                "message": "Missing Content-Security-Policy",
            })
            score -= 30

        # Check HSTS
        if "strict-transport-security" not in headers:
            issues.append({
                "header": "HSTS",
                "severity": "critical",
                "message": "Missing HSTS",
            })
            score -= 30

        # Check X-Frame-Options
        if "x-frame-options" not in headers:
            issues.append({
                "header": "X-Frame-Options",
                "severity": "medium",
                "message": "Missing X-Frame-Options",
            })
            score -= 20

        # Check X-Content-Type-Options
        if "x-content-type-options" not in headers:
            issues.append({
                "header": "X-Content-Type-Options",
                "severity": "medium",
                "message": "Missing X-Content-Type-Options",
            })
            score -= 20

        # Check X-XSS-Protection (deprecated but still checked)
        if "x-xss-protection" not in headers:
            issues.append({
                "header": "X-XSS-Protection",
                "severity": "low",
                "message": "Missing X-XSS-Protection",
            })
            score -= 5

        return {
            "url": url,
            "headers": dict(response.headers),
            "issues": issues,
            "score": max(0, score),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
