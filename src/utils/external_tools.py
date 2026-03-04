"""
External Tool Wrapper Framework

Provides utilities for detecting, running, and managing external pentesting tools.
Supports timeout handling, version detection, and cross-platform compatibility.
"""
import re
import shutil
import subprocess
from typing import Optional, Tuple


# Tool registry with version detection metadata
TOOLS = {
    'nmap': {
        'version_flag': '--version',
        'version_regex': r'Nmap version (\d+\.\d+(?:\.\d+)?)',
        'description': 'Network scanner and security auditing tool',
    },
    'hashcat': {
        'version_flag': '--version',
        'version_regex': r'v(\d+\.\d+\.\d+)',
        'description': 'Advanced password recovery utility',
    },
    'john': {
        'version_flag': '--version',
        'version_regex': r'John the Ripper ([\d\.]+-[\w-]+)',
        'description': 'Password cracker',
    },
    'sublist3r': {
        'version_flag': '--version',
        'version_regex': r'(\d+\.\d+(?:\.\d+)?)',
        'description': 'Subdomain enumeration tool',
    },
}


class ExternalTool:
    """
    Wrapper for external pentesting tools.
    Provides detection, execution, and version parsing.
    """
    
    @staticmethod
    def detect_tool(name: str) -> Optional[str]:
        """
        Detect if tool exists in PATH and return its version.
        
        Args:
            name: Tool name to detect (e.g., 'nmap', 'hashcat')
        
        Returns:
            Version string if tool is found, None otherwise
        """
        # Check if tool exists in PATH using cross-platform method
        tool_path = shutil.which(name)
        if tool_path is None:
            return None
        
        # Try to get version if tool is registered
        if name in TOOLS:
            version_flag = TOOLS[name]['version_flag']
            try:
                # Run tool with version flag
                stdout, stderr, code = ExternalTool.run_tool([name, version_flag], timeout=5)
                
                # Try to parse version from output
                output = stdout + stderr
                version = ExternalTool.parse_version(name, output)
                if version:
                    return version
                
                # If parsing failed but tool exists, return generic indicator
                return 'unknown'
            except Exception:
                # Tool exists but version detection failed
                return 'unknown'
        
        # Tool not in registry but exists in PATH
        return 'detected'
    
    @staticmethod
    def run_tool(cmd: list, timeout: int = 60) -> Tuple[str, str, int]:
        """
        Run external tool with timeout protection.
        
        Args:
            cmd: Command list (e.g., ['nmap', '-sV', 'target.com'])
            timeout: Maximum execution time in seconds (default: 60)
        
        Returns:
            Tuple of (stdout, stderr, return_code)
        
        Raises:
            subprocess.TimeoutExpired: If command exceeds timeout
        """
        try:
            result = subprocess.run(
                cmd,
                timeout=timeout,
                capture_output=True,
                text=True,
                shell=False,
            )
            return result.stdout, result.stderr, result.returncode
        
        except subprocess.TimeoutExpired as e:
            # Re-raise timeout exception for caller to handle
            raise e
    
    @staticmethod
    def parse_version(tool_name: str, output: str) -> Optional[str]:
        """
        Parse version string from tool output using registered regex patterns.
        
        Args:
            tool_name: Name of the tool (must be in TOOLS registry)
            output: Raw output from tool (stdout + stderr)
        
        Returns:
            Extracted version string or None if not found
        """
        if tool_name not in TOOLS:
            return None
        
        version_regex = TOOLS[tool_name]['version_regex']
        match = re.search(version_regex, output)
        
        if match:
            return match.group(1)
        
        return None
