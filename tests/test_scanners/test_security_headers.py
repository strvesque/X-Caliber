import asyncio
import pytest

from src.scanners.security_headers import SecurityHeadersAnalyzer


class DummyResponse:
    def __init__(self, headers):
        # httpx stores headers in a case-insensitive mapping but items() yields
        # canonical header names; we keep simple dict here
        self._headers = headers

    @property
    def headers(self):
        return self._headers


class DummyAsyncClient:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def head(self, url, follow_redirects=True):
        return self._response


@pytest.mark.asyncio
async def test_all_headers_present(monkeypatch):
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
    }

    resp = DummyResponse(headers)
    client = DummyAsyncClient(resp)

    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: client)

    analyzer = SecurityHeadersAnalyzer()
    result = await analyzer.analyze("https://example.com")

    assert result["url"] == "https://example.com"
    assert result["score"] == 100
    assert result["issues"] == []
    assert "Content-Security-Policy" in result["headers"]


@pytest.mark.asyncio
async def test_missing_csp_and_hsts(monkeypatch):
    headers = {
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
    }

    resp = DummyResponse(headers)
    client = DummyAsyncClient(resp)
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: client)

    analyzer = SecurityHeadersAnalyzer()
    result = await analyzer.analyze("http://no-secure.com")

    # missing CSP (-30) and HSTS (-30) and X-XSS-Protection (-5) = -65 -> score 35
    assert result["score"] == 35
    found = {i["header"] for i in result["issues"]}
    assert "CSP" in found and "HSTS" in found and "X-XSS-Protection" in found


@pytest.mark.asyncio
async def test_missing_frame_and_content_type_options(monkeypatch):
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
    }

    resp = DummyResponse(headers)
    client = DummyAsyncClient(resp)
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: client)

    analyzer = SecurityHeadersAnalyzer()
    result = await analyzer.analyze("https://partial.com")

    # missing X-Frame-Options (-20), X-Content-Type-Options (-20), X-XSS-Protection (-5)
    assert result["score"] == 55
    headers_back = {k.lower(): v for k, v in result["headers"].items()}
    assert "content-security-policy" in headers_back


@pytest.mark.asyncio
async def test_no_headers(monkeypatch):
    resp = DummyResponse({})
    client = DummyAsyncClient(resp)
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: client)

    analyzer = SecurityHeadersAnalyzer()
    result = await analyzer.analyze("https://empty.com")

    # all missing: -30 -30 -20 -20 -5 = -105 -> score floored at 0
    assert result["score"] == 0
    assert len(result["issues"]) == 5


@pytest.mark.asyncio
async def test_headers_case_insensitivity(monkeypatch):
    # Mixed casing to ensure we lower-case keys internally
    headers = {
        "content-security-policy": "default-src 'self'",
        "STRICT-TRANSPORT-SECURITY": "max-age=31536000",
        "x-frame-options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "x-xss-protection": "1; mode=block",
    }

    resp = DummyResponse(headers)
    client = DummyAsyncClient(resp)
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: client)

    analyzer = SecurityHeadersAnalyzer()
    result = await analyzer.analyze("https://case.com")

    assert result["score"] == 100


@pytest.mark.asyncio
async def test_timestamp_and_url(monkeypatch):
    headers = {"X-Frame-Options": "SAMEORIGIN"}
    resp = DummyResponse(headers)
    client = DummyAsyncClient(resp)
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: client)

    analyzer = SecurityHeadersAnalyzer()
    result = await analyzer.analyze("https://time.com")

    assert result["url"] == "https://time.com"
    assert "timestamp" in result


@pytest.mark.asyncio
async def test_realistic_header_values_do_not_affect_presence(monkeypatch):
    headers = {
        "Content-Security-Policy": "script-src 'self' https://apis.example.com; object-src 'none';",
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "X-Frame-Options": "ALLOW-FROM https://example.com",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "0",
    }

    resp = DummyResponse(headers)
    client = DummyAsyncClient(resp)
    monkeypatch.setattr("httpx.AsyncClient", lambda *a, **k: client)

    analyzer = SecurityHeadersAnalyzer()
    result = await analyzer.analyze("https://realistic.com")

    assert result["score"] == 100


def test_main_list_plugins_and_check_tools(capsys):
    # Call main with --list-plugins and --check-tools to exercise CLI branches
    from src import main as _main

    assert _main.main(["--list-plugins"]) == 0
    assert _main.main(["--check-tools"]) == 0
    # capture printed output to ensure the branches ran
    captured = capsys.readouterr()
    assert "No plugins installed" in captured.out or "Tool check" in captured.out
