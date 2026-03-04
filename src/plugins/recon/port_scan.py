"""Port scanner plugin using nmap.

Wraps nmap for network port scanning with XML output parsing.
Provides port enumeration, service detection, and version identification.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - for static typing only
    from src.core.plugin import BasePlugin  # type: ignore
else:
    # Minimal runtime stub so module can be imported outside of the plugin runner
    class BasePlugin:  # pragma: no cover - runtime stub only
        def init(self, config: Dict[str, Any]) -> None:
            raise NotImplementedError

        def run(self, params: Dict[str, Any]) -> None:
            raise NotImplementedError

        def stop(self) -> None:
            pass

        def get_results(self) -> Dict[str, Any]:
            return {}


class PortScannerPlugin(BasePlugin):
    """Plugin that scans network ports using nmap.

    Wraps nmap with XML output parsing for structured results.
    """

    name = "Port Scanner"
    category = "recon"
    description = "Network port scanner using nmap with service detection"
    version = "1.0.0"

    def __init__(self) -> None:
        self._config: Dict[str, Any] = {}
        self._result: Dict[str, Any] = {}

    def init(self, config: Dict[str, Any]) -> None:
        """Store configuration."""
        self._config = dict(config or {})

    def _validate_params(self, params: Dict[str, Any]) -> None:
        """Validate required parameters."""
        if not isinstance(params, dict):
            raise ValueError("params must be a dict")

        if "target" not in params:
            raise ValueError("Missing required param: target")

        target = params.get("target")
        if not isinstance(target, str) or not target:
            raise ValueError("target must be a non-empty string")

    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """Parse nmap XML output and extract port information.

        Args:
            xml_output: Raw XML output from nmap -oX

        Returns:
            Dict with target, ports list, and OS info
        """
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError as e:
            return {"error": f"Failed to parse nmap XML: {e}"}

        result: Dict[str, Any] = {
            "target": "",
            "ports": [],
            "os": ""
        }

        # Extract host address
        host = root.find(".//host")
        if host is not None:
            address = host.find(".//address[@addrtype='ipv4']")
            if address is None:
                address = host.find(".//address[@addrtype='ipv6']")
            if address is not None:
                result["target"] = address.get("addr", "")

        # Extract ports
        ports = root.findall(".//port")
        for port in ports:
            port_info: Dict[str, Any] = {}

            # Port number and protocol
            port_info["port"] = int(port.get("portid", 0))
            port_info["protocol"] = port.get("protocol", "tcp")

            # State
            state = port.find("state")
            if state is not None:
                port_info["state"] = state.get("state", "unknown")
            else:
                port_info["state"] = "unknown"

            # Service info
            service = port.find("service")
            if service is not None:
                port_info["service"] = service.get("name", "unknown")
                port_info["product"] = service.get("product", "")
                port_info["version"] = service.get("version", "")
            else:
                port_info["service"] = "unknown"
                port_info["product"] = ""
                port_info["version"] = ""

            result["ports"].append(port_info)

        # Extract OS detection (if available)
        osmatch = root.find(".//osmatch")
        if osmatch is not None:
            result["os"] = osmatch.get("name", "")

        return result

    def run(self, params: Dict[str, Any]) -> None:
        """Run nmap port scan.

        Expected params:
            {
                'target': str,  # IP address or hostname
                'ports': str,   # Optional: port range (e.g., '22,80,443' or '1-1000')
                'scan_type': str  # Optional: 'syn'|'tcp'|'udp' (default: syn)
            }
        """
        self._validate_params(params)

        # Check if nmap is available
        from src.utils.external_tools import ExternalTool

        nmap_version = ExternalTool.detect_tool("nmap")
        if nmap_version is None:
            self._result = {
                "error": "nmap not found. Install with: apt install nmap (Linux) or brew install nmap (macOS)"
            }
            return

        target = params["target"]
        ports = params.get("ports", "22,80,443,8080")  # Common ports by default
        scan_type = params.get("scan_type", "syn")

        # Build nmap command
        cmd = ["nmap", "-oX", "-"]  # XML output to stdout

        # Scan type flags
        if scan_type == "syn":
            cmd.append("-sS")  # SYN scan (requires root)
        elif scan_type == "tcp":
            cmd.append("-sT")  # TCP connect scan
        elif scan_type == "udp":
            cmd.append("-sU")  # UDP scan
        else:
            cmd.append("-sT")  # Default to TCP

        # Port specification
        if ports:
            cmd.extend(["-p", str(ports)])

        # Service version detection
        cmd.append("-sV")

        # Target
        cmd.append(target)

        # Run nmap
        try:
            stdout, stderr, exit_code = ExternalTool.run_tool(cmd, timeout=120)

            if exit_code != 0:
                self._result = {
                    "error": f"nmap failed with exit code {exit_code}",
                    "stderr": stderr
                }
                return

            # Parse XML output
            parsed = self._parse_nmap_xml(stdout)
            self._result = parsed

        except Exception as e:
            self._result = {
                "error": f"Failed to run nmap: {str(e)}"
            }

    def stop(self) -> None:
        """No-op cleanup hook required by BasePlugin interface."""
        pass

    def get_results(self) -> Dict[str, Any]:
        """Return scan results."""
        return dict(self._result)
