"""Tests for WebVulnScanner - Custom vulnerability scanner."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.scanners.web_vuln_scanner import (
    WebVulnScanner,
    WebVulnScannerError,
    WebVulnScannerTimeoutError,
)


class TestWebVulnScannerInit:
    """Test WebVulnScanner initialization."""

    def test_init_default_values(self):
        """Test scanner initializes with default timeout."""
        scanner = WebVulnScanner()
        assert scanner.timeout == 10.0
        assert scanner.rate_limit_delay == 1.0

    def test_init_custom_timeout(self):
        """Test scanner initializes with custom timeout."""
        scanner = WebVulnScanner(timeout=20.0)
        assert scanner.timeout == 20.0

    def test_init_custom_rate_limit(self):
        """Test scanner initializes with custom rate limit delay."""
        scanner = WebVulnScanner(rate_limit_delay=2.0)
        assert scanner.rate_limit_delay == 2.0


class TestSQLiDetection:
    """Test SQL injection detection."""

    @pytest.mark.asyncio
    async def test_sqli_detected_with_error_pattern(self):
        """Test SQLi detected when error patterns found in response."""
        scanner = WebVulnScanner(timeout=10.0)
        
        mock_response = MagicMock()
        mock_response.text = "MySQL syntax error near '1' OR '1'='1'"
        mock_response.status_code = 500
        mock_response.url = "http://example.com/page?id=1'"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            results = await scanner.scan_sqli("http://example.com/page", {"id": "1"})
        
        assert len(results) > 0
        assert results[0]["type"] == "sqli"
        assert "MySQL" in results[0]["evidence"] or "syntax" in results[0]["evidence"]
        assert results[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_sqli_not_detected_clean_response(self):
        """Test SQLi not detected when response is clean."""
        scanner = WebVulnScanner(timeout=10.0)
        
        mock_response = MagicMock()
        mock_response.text = "Welcome to our homepage"
        mock_response.status_code = 200
        mock_response.url = "http://example.com/page?id=1"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            results = await scanner.scan_sqli("http://example.com/page", {"id": "1"})
        
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_sqli_multiple_payloads_tested(self):
        """Test multiple SQL injection payloads are tested."""
        scanner = WebVulnScanner(timeout=10.0)
        
        mock_response = MagicMock()
        mock_response.text = "No errors"
        mock_response.status_code = 200
        mock_response.url = "http://example.com/page"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            await scanner.scan_sqli("http://example.com/page", {"id": "1"})
            
            # Should test multiple payloads (at least 4)
            assert mock_client_instance.get.call_count >= 4

    @pytest.mark.asyncio
    async def test_sqli_timeout_error(self):
        """Test SQLi scan raises timeout error."""
        scanner = WebVulnScanner(timeout=0.001)
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            with pytest.raises(WebVulnScannerTimeoutError):
                await scanner.scan_sqli("http://example.com/page", {"id": "1"})


class TestXSSDetection:
    """Test XSS detection."""

    @pytest.mark.asyncio
    async def test_xss_detected_reflected_payload(self):
        """Test XSS detected when payload reflected unescaped."""
        scanner = WebVulnScanner(timeout=10.0)
        
        mock_response = MagicMock()
        mock_response.text = "<html><body><script>alert(xss)</script></body></html>"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        mock_response.url = "http://example.com/search?q=<script>alert(xss)</script>"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            results = await scanner.scan_xss("http://example.com/search", {"q": "test"})
        
        assert len(results) > 0
        assert results[0]["type"] == "xss"
        assert results[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_xss_not_detected_escaped_payload(self):
        """Test XSS not detected when payload is escaped."""
        scanner = WebVulnScanner(timeout=10.0)
        
        mock_response = MagicMock()
        mock_response.text = "<html><body>&lt;script&gt;alert(xss)&lt;/script&gt;</body></html>"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        mock_response.url = "http://example.com/search?q=test"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            results = await scanner.scan_xss("http://example.com/search", {"q": "test"})
        
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_xss_not_detected_non_html_response(self):
        """Test XSS not detected for non-HTML content types."""
        scanner = WebVulnScanner(timeout=10.0)
        
        mock_response = MagicMock()
        mock_response.text = "<script>alert(xss)</script>"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.url = "http://example.com/api?q=test"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            results = await scanner.scan_xss("http://example.com/api", {"q": "test"})
        
        assert len(results) == 0


class TestCSRFDetection:
    """Test CSRF protection detection."""

    @pytest.mark.asyncio
    async def test_csrf_missing_token_in_form(self):
        """Test CSRF vulnerability detected when token missing."""
        scanner = WebVulnScanner(timeout=10.0)
        
        html = """
        <html>
        <body>
            <form method="post" action="/submit">
                <input type="text" name="username">
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        """
        
        mock_response = MagicMock()
        mock_response.text = html
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            result = await scanner.scan_csrf("http://example.com/login")
        
        assert result["vulnerable"] is True
        assert len(result["forms_without_csrf"]) > 0
        assert result["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_csrf_token_present(self):
        """Test CSRF not detected when token present."""
        scanner = WebVulnScanner(timeout=10.0)
        
        html = """
        <html>
        <body>
            <form method="post" action="/submit">
                <input type="hidden" name="csrf_token" value="abc123">
                <input type="text" name="username">
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        """
        
        mock_response = MagicMock()
        mock_response.text = html
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            result = await scanner.scan_csrf("http://example.com/login")
        
        assert result["vulnerable"] is False
        assert len(result["forms_without_csrf"]) == 0

    @pytest.mark.asyncio
    async def test_csrf_no_forms_present(self):
        """Test CSRF scan when no forms present."""
        scanner = WebVulnScanner(timeout=10.0)
        
        html = """
        <html>
        <body>
            <h1>Welcome</h1>
            <p>No forms here</p>
        </body>
        </html>
        """
        
        mock_response = MagicMock()
        mock_response.text = html
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            result = await scanner.scan_csrf("http://example.com")
        
        assert result["vulnerable"] is False
        assert len(result["forms_without_csrf"]) == 0


class TestScanAll:
    """Test scan_all method."""

    @pytest.mark.asyncio
    async def test_scan_all_runs_all_scans(self):
        """Test scan_all executes all three scan types."""
        scanner = WebVulnScanner(timeout=10.0)
        
        mock_response = MagicMock()
        mock_response.text = "<html><body>Clean page</body></html>"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        mock_response.url = "http://example.com"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            result = await scanner.scan_all("http://example.com")
        
        assert "url" in result
        assert "vulnerabilities" in result
        assert "scan_time" in result
        assert "timestamp" in result
        assert result["url"] == "http://example.com"

    @pytest.mark.asyncio
    async def test_scan_all_includes_all_vulnerability_types(self):
        """Test scan_all result structure includes all vuln types."""
        scanner = WebVulnScanner(timeout=10.0)
        
        mock_response = MagicMock()
        mock_response.text = "<html><body>Test</body></html>"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        mock_response.url = "http://example.com"
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            result = await scanner.scan_all("http://example.com")
        
        vulns = result["vulnerabilities"]
        assert "sqli" in vulns
        assert "xss" in vulns
        assert "csrf" in vulns
        assert isinstance(vulns["sqli"], list)
        assert isinstance(vulns["xss"], list)
        assert isinstance(vulns["csrf"], dict)

    @pytest.mark.asyncio
    async def test_scan_all_respects_rate_limiting(self):
        """Test scan_all applies rate limiting between requests."""
        scanner = WebVulnScanner(timeout=10.0, rate_limit_delay=0.1)
        
        mock_response = MagicMock()
        mock_response.text = "Test"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html"}
        mock_response.url = "http://example.com"
        
        with patch("httpx.AsyncClient") as mock_client, \
             patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__.return_value = mock_client_instance
            
            await scanner.scan_all("http://example.com")
            
            # Should have rate limiting delays
            assert mock_sleep.call_count > 0
