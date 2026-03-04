"""Subdomain enumeration plugin using sublist3r.

Wraps sublist3r for subdomain discovery and enumeration.
Provides subdomain detection using multiple search engines.
"""
from __future__ import annotations

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


class SubdomainEnumPlugin(BasePlugin):
    """Plugin that enumerates subdomains using sublist3r.

    Wraps sublist3r with output parsing for structured results.
    """

    name = "Subdomain Enumerator"
    category = "recon"
    description = "Subdomain enumeration using sublist3r and search engines"
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

        if "domain" not in params:
            raise ValueError("Missing required param: domain")

        domain = params.get("domain")
        if not isinstance(domain, str) or not domain:
            raise ValueError("domain must be a non-empty string")

    def _parse_sublist3r_output(self, stdout: str) -> Dict[str, Any]:
        """Parse sublist3r console output and extract subdomains.

        Args:
            stdout: Raw stdout from sublist3r

        Returns:
            Dict with domain, subdomains list, and count
        """
        subdomains = []
        
        # Parse line by line
        for line in stdout.splitlines():
            line = line.strip()
            
            # Skip empty lines and headers
            if not line or line.startswith("[-]") or line.startswith("[+]"):
                continue
            
            # Skip lines that don't look like domains (no dots)
            if "." not in line:
                continue
            
            # Skip lines with special characters that aren't domains
            if any(char in line for char in ["[", "]", ":", "/"]):
                continue
            
            # This line looks like a subdomain
            subdomains.append(line)
        
        return {
            "domain": "",  # Will be set by caller
            "subdomains": subdomains,
            "count": len(subdomains)
        }

    def run(self, params: Dict[str, Any]) -> None:
        """Run sublist3r subdomain enumeration.

        Expected params:
            {
                'domain': str,  # Domain to enumerate (e.g., 'example.com')
                'engines': str,  # Optional: comma-separated engines (e.g., 'google,bing')
            }
        """
        self._validate_params(params)

        # Check if sublist3r is available
        from src.utils.external_tools import ExternalTool

        sublist3r_version = ExternalTool.detect_tool("sublist3r")
        if sublist3r_version is None:
            self._result = {
                "error": "sublist3r not found. Install with: pip install sublist3r"
            }
            return

        domain = params["domain"]
        engines = params.get("engines", "")  # Empty string uses all engines

        # Build sublist3r command
        cmd = ["sublist3r", "-d", domain]

        # Specific engines (optional)
        if engines:
            cmd.extend(["-e", engines])

        # No verbose output
        cmd.append("-o")
        cmd.append("/dev/null")  # Suppress file output, we'll parse stdout

        # Run sublist3r with 60s timeout
        try:
            stdout, stderr, exit_code = ExternalTool.run_tool(cmd, timeout=60)

            # sublist3r may return non-zero even on success, check for actual output
            if stdout or stderr:
                # Parse output (try both stdout and stderr as sublist3r may use either)
                combined_output = stdout + "\n" + stderr
                parsed = self._parse_sublist3r_output(combined_output)
                parsed["domain"] = domain
                
                # Add timeout warning if we got partial results but hit timeout
                if exit_code != 0 and parsed["count"] > 0:
                    parsed["warning"] = "Enumeration may be incomplete (timeout or partial failure)"
                
                self._result = parsed
            else:
                self._result = {
                    "error": f"sublist3r produced no output (exit code: {exit_code})",
                    "stderr": stderr
                }

        except Exception as e:
            # Check if it's a timeout
            import subprocess
            if isinstance(e, subprocess.TimeoutExpired):
                self._result = {
                    "error": "sublist3r timed out after 60 seconds",
                    "warning": "Consider enumerating with fewer engines or a more specific domain"
                }
            else:
                self._result = {
                    "error": f"Failed to run sublist3r: {str(e)}"
                }

    def stop(self) -> None:
        """No-op cleanup hook required by BasePlugin interface."""
        pass

    def get_results(self) -> Dict[str, Any]:
        """Return enumeration results."""
        return dict(self._result)
