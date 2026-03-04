"""Tests for subdomain enumerator plugin."""
from unittest.mock import patch
import subprocess
import pytest


def test_subdomain_plugin_metadata():
    """Test that plugin has correct metadata."""
    from src.plugins.recon.subdomain import SubdomainEnumPlugin
    
    plugin = SubdomainEnumPlugin()
    assert plugin.name == "Subdomain Enumerator"
    assert plugin.category == "recon"
    assert plugin.description
    assert plugin.version


def test_subdomain_validates_params():
    """Test parameter validation."""
    from src.plugins.recon.subdomain import SubdomainEnumPlugin
    
    plugin = SubdomainEnumPlugin()
    plugin.init({})
    
    # Missing domain
    with pytest.raises(ValueError, match="Missing required param: domain"):
        plugin.run({})
    
    # Empty domain
    with pytest.raises(ValueError, match="domain must be a non-empty string"):
        plugin.run({"domain": ""})
    
    # Invalid domain type
    with pytest.raises(ValueError, match="domain must be a non-empty string"):
        plugin.run({"domain": 123})


@patch("src.utils.external_tools.ExternalTool")
def test_subdomain_handles_missing_tool(mock_external_tool):
    """Test graceful error when sublist3r is not installed."""
    from src.plugins.recon.subdomain import SubdomainEnumPlugin
    
    # Mock sublist3r not found
    mock_external_tool.detect_tool.return_value = None
    
    plugin = SubdomainEnumPlugin()
    plugin.init({})
    plugin.run({"domain": "example.com"})
    
    results = plugin.get_results()
    assert "error" in results
    assert "sublist3r not found" in results["error"]
    assert "pip install sublist3r" in results["error"]


@patch("src.utils.external_tools.ExternalTool")
def test_subdomain_parses_output(mock_external_tool):
    """Test output parsing with mock sublist3r output."""
    from src.plugins.recon.subdomain import SubdomainEnumPlugin
    
    # Mock sublist3r available
    mock_external_tool.detect_tool.return_value = "1.0"
    
    # Mock sublist3r output (typical format)
    mock_output = """[-] Enumerating subdomains now for example.com
[-] Searching now in Google..
www.example.com
mail.example.com
ftp.example.com
[-] Searching now in Bing..
api.example.com
[-] Total Unique Subdomains Found: 4
"""
    
    mock_external_tool.run_tool.return_value = (mock_output, "", 0)
    
    plugin = SubdomainEnumPlugin()
    plugin.init({})
    plugin.run({"domain": "example.com"})
    
    results = plugin.get_results()
    
    # Verify domain
    assert results["domain"] == "example.com"
    
    # Verify subdomains
    assert len(results["subdomains"]) == 4
    assert "www.example.com" in results["subdomains"]
    assert "mail.example.com" in results["subdomains"]
    assert "ftp.example.com" in results["subdomains"]
    assert "api.example.com" in results["subdomains"]
    
    # Verify count
    assert results["count"] == 4


@patch("src.utils.external_tools.ExternalTool")
def test_subdomain_handles_no_results(mock_external_tool):
    """Test handling when no subdomains are found."""
    from src.plugins.recon.subdomain import SubdomainEnumPlugin
    
    mock_external_tool.detect_tool.return_value = "1.0"
    
    # Empty output
    mock_output = """[-] Enumerating subdomains now for nonexistent.invalid
[-] Total Unique Subdomains Found: 0
"""
    
    mock_external_tool.run_tool.return_value = (mock_output, "", 0)
    
    plugin = SubdomainEnumPlugin()
    plugin.init({})
    plugin.run({"domain": "nonexistent.invalid"})
    
    results = plugin.get_results()
    assert results["domain"] == "nonexistent.invalid"
    assert results["subdomains"] == []
    assert results["count"] == 0


@patch("src.utils.external_tools.ExternalTool")
def test_subdomain_handles_timeout(mock_external_tool):
    """Test timeout handling."""
    from src.plugins.recon.subdomain import SubdomainEnumPlugin
    
    mock_external_tool.detect_tool.return_value = "1.0"
    
    # Mock timeout exception
    mock_external_tool.run_tool.side_effect = subprocess.TimeoutExpired(cmd="sublist3r", timeout=60)
    
    plugin = SubdomainEnumPlugin()
    plugin.init({})
    plugin.run({"domain": "example.com"})
    
    results = plugin.get_results()
    assert "error" in results
    assert "timed out" in results["error"]
    assert "warning" in results


@patch("src.utils.external_tools.ExternalTool")
def test_subdomain_builds_correct_command(mock_external_tool):
    """Test that sublist3r command is built correctly."""
    from src.plugins.recon.subdomain import SubdomainEnumPlugin
    
    mock_external_tool.detect_tool.return_value = "1.0"
    mock_external_tool.run_tool.return_value = ("www.test.com\n", "", 0)
    
    plugin = SubdomainEnumPlugin()
    plugin.init({})
    
    # Test with engines
    plugin.run({"domain": "test.com", "engines": "google,bing"})
    call_args = mock_external_tool.run_tool.call_args
    cmd = call_args[0][0]
    assert "sublist3r" in cmd
    assert "-d" in cmd
    assert "test.com" in cmd
    assert "-e" in cmd
    assert "google,bing" in cmd
    
    # Verify timeout parameter
    assert call_args[1]["timeout"] == 60


@patch("src.utils.external_tools.ExternalTool")
def test_subdomain_filters_invalid_lines(mock_external_tool):
    """Test that parsing filters out non-domain lines."""
    from src.plugins.recon.subdomain import SubdomainEnumPlugin
    
    mock_external_tool.detect_tool.return_value = "1.0"
    
    # Output with various invalid lines
    mock_output = """[-] Header line
[+] Another header
valid.example.com
not_a_subdomain_no_dots
line:with:colons
line/with/slashes
another.valid.example.com
"""
    
    mock_external_tool.run_tool.return_value = (mock_output, "", 0)
    
    plugin = SubdomainEnumPlugin()
    plugin.init({})
    plugin.run({"domain": "example.com"})
    
    results = plugin.get_results()
    
    # Should only have the 2 valid subdomains
    assert results["count"] == 2
    assert "valid.example.com" in results["subdomains"]
    assert "another.valid.example.com" in results["subdomains"]


@patch("src.utils.external_tools.ExternalTool")
def test_subdomain_handles_stderr_output(mock_external_tool):
    """Test parsing when sublist3r outputs to stderr instead of stdout."""
    from src.plugins.recon.subdomain import SubdomainEnumPlugin
    
    mock_external_tool.detect_tool.return_value = "1.0"
    
    # Sometimes sublist3r outputs to stderr
    mock_stderr = """stderr.example.com
another.example.com
"""
    
    mock_external_tool.run_tool.return_value = ("", mock_stderr, 0)
    
    plugin = SubdomainEnumPlugin()
    plugin.init({})
    plugin.run({"domain": "example.com"})
    
    results = plugin.get_results()
    assert results["count"] == 2
    assert "stderr.example.com" in results["subdomains"]
    assert "another.example.com" in results["subdomains"]


def test_subdomain_stop_method():
    """Test stop method (no-op for this plugin)."""
    from src.plugins.recon.subdomain import SubdomainEnumPlugin
    
    plugin = SubdomainEnumPlugin()
    plugin.stop()  # Should not raise
