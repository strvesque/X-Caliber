"""Tests for port scanner plugin."""
from unittest.mock import patch, MagicMock
import pytest


def test_port_scanner_plugin_metadata():
    """Test that plugin has correct metadata."""
    from src.plugins.recon.port_scan import PortScannerPlugin
    
    plugin = PortScannerPlugin()
    assert plugin.name == "Port Scanner"
    assert plugin.category == "recon"
    assert plugin.description
    assert plugin.version


def test_port_scanner_validates_params():
    """Test parameter validation."""
    from src.plugins.recon.port_scan import PortScannerPlugin
    
    plugin = PortScannerPlugin()
    plugin.init({})
    
    # Missing target
    with pytest.raises(ValueError, match="Missing required param: target"):
        plugin.run({})
    
    # Empty target
    with pytest.raises(ValueError, match="target must be a non-empty string"):
        plugin.run({"target": ""})
    
    # Invalid target type
    with pytest.raises(ValueError, match="target must be a non-empty string"):
        plugin.run({"target": 123})


@patch("src.utils.external_tools.ExternalTool")
def test_port_scanner_handles_missing_nmap(mock_external_tool):
    """Test graceful error when nmap is not installed."""
    from src.plugins.recon.port_scan import PortScannerPlugin
    
    # Mock nmap not found
    mock_external_tool.detect_tool.return_value = None
    
    plugin = PortScannerPlugin()
    plugin.init({})
    plugin.run({"target": "127.0.0.1"})
    
    results = plugin.get_results()
    assert "error" in results
    assert "nmap not found" in results["error"]
    assert "apt install nmap" in results["error"] or "brew install nmap" in results["error"]


@patch("src.utils.external_tools.ExternalTool")
def test_port_scanner_parses_xml_output(mock_external_tool):
    """Test XML parsing with mock nmap output."""
    from src.plugins.recon.port_scan import PortScannerPlugin
    
    # Mock nmap available
    mock_external_tool.detect_tool.return_value = "7.80"
    
    # Mock nmap XML output
    mock_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.41"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.x"/>
    </os>
  </host>
</nmaprun>
"""
    
    mock_external_tool.run_tool.return_value = (mock_xml, "", 0)
    
    plugin = PortScannerPlugin()
    plugin.init({})
    plugin.run({"target": "127.0.0.1", "ports": "22,80"})
    
    results = plugin.get_results()
    
    # Verify target
    assert results["target"] == "127.0.0.1"
    
    # Verify ports
    assert len(results["ports"]) == 2
    
    # Check port 22
    port_22 = next(p for p in results["ports"] if p["port"] == 22)
    assert port_22["state"] == "open"
    assert port_22["service"] == "ssh"
    assert port_22["product"] == "OpenSSH"
    assert port_22["version"] == "8.2"
    
    # Check port 80
    port_80 = next(p for p in results["ports"] if p["port"] == 80)
    assert port_80["state"] == "open"
    assert port_80["service"] == "http"
    
    # Check OS detection
    assert results["os"] == "Linux 5.x"


@patch("src.utils.external_tools.ExternalTool")
def test_port_scanner_handles_nmap_failure(mock_external_tool):
    """Test error handling when nmap exits with non-zero code."""
    from src.plugins.recon.port_scan import PortScannerPlugin
    
    mock_external_tool.detect_tool.return_value = "7.80"
    mock_external_tool.run_tool.return_value = ("", "Error: Invalid target", 1)
    
    plugin = PortScannerPlugin()
    plugin.init({})
    plugin.run({"target": "invalid_target"})
    
    results = plugin.get_results()
    assert "error" in results
    assert "nmap failed" in results["error"]


@patch("src.utils.external_tools.ExternalTool")
def test_port_scanner_builds_correct_command(mock_external_tool):
    """Test that nmap command is built correctly with different scan types."""
    from src.plugins.recon.port_scan import PortScannerPlugin
    
    mock_external_tool.detect_tool.return_value = "7.80"
    mock_external_tool.run_tool.return_value = ("<nmaprun><host></host></nmaprun>", "", 0)
    
    plugin = PortScannerPlugin()
    plugin.init({})
    
    # Test SYN scan (default)
    plugin.run({"target": "192.168.1.1", "ports": "1-1000", "scan_type": "syn"})
    call_args = mock_external_tool.run_tool.call_args
    cmd = call_args[0][0]
    assert "nmap" in cmd
    assert "-oX" in cmd
    assert "-sS" in cmd  # SYN scan
    assert "-p" in cmd
    assert "1-1000" in cmd
    assert "192.168.1.1" in cmd
    
    # Test TCP scan
    plugin.run({"target": "192.168.1.1", "scan_type": "tcp"})
    call_args = mock_external_tool.run_tool.call_args
    cmd = call_args[0][0]
    assert "-sT" in cmd  # TCP connect scan


@patch("src.utils.external_tools.ExternalTool")
def test_port_scanner_handles_invalid_xml(mock_external_tool):
    """Test handling of malformed XML output."""
    from src.plugins.recon.port_scan import PortScannerPlugin
    
    mock_external_tool.detect_tool.return_value = "7.80"
    mock_external_tool.run_tool.return_value = ("<invalid xml", "", 0)
    
    plugin = PortScannerPlugin()
    plugin.init({})
    plugin.run({"target": "127.0.0.1"})
    
    results = plugin.get_results()
    assert "error" in results
    assert "Failed to parse" in results["error"]


def test_port_scanner_stop_method():
    """Test stop method (no-op for this plugin)."""
    from src.plugins.recon.port_scan import PortScannerPlugin
    
    plugin = PortScannerPlugin()
    plugin.stop()  # Should not raise


def test_port_scanner_empty_ports_list():
    """Test parsing when no ports are found."""
    from src.plugins.recon.port_scan import PortScannerPlugin
    
    plugin = PortScannerPlugin()
    
    # XML with no open ports
    mock_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
    </ports>
  </host>
</nmaprun>
"""
    
    result = plugin._parse_nmap_xml(mock_xml)
    assert result["target"] == "127.0.0.1"
    assert result["ports"] == []
