"""Hash identification and cracking plugin.

Identifies hash types using hashid library and cracks hashes using hashcat or John the Ripper.
Provides both identification and cracking capabilities for password hashes.
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


class HashCrackerPlugin(BasePlugin):
    """Plugin that identifies and cracks password hashes.

    Uses hashid for identification and hashcat/john for cracking.
    """

    name = "Hash Identifier & Cracker"
    category = "crypto"
    description = "Identify hash types and crack passwords using hashcat/john"
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

        if "hash" not in params:
            raise ValueError("Missing required param: hash")

        hash_val = params.get("hash")
        if not isinstance(hash_val, str) or not hash_val:
            raise ValueError("hash must be a non-empty string")

        mode = params.get("mode", "identify")
        if mode not in ("identify", "crack"):
            raise ValueError("mode must be 'identify' or 'crack'")

    def _identify_hash(self, hash_val: str) -> Dict[str, Any]:
        """Identify hash type using hashid library.

        Args:
            hash_val: Hash string to identify

        Returns:
            Dict with hash type and possible types
        """
        try:
            import hashid
        except ImportError:
            return {
                "error": "hashid library not found. Install with: pip install hashid"
            }

        try:
            hash_identifier = hashid.HashID()
            results = hash_identifier.identifyHash(hash_val)
            
            if not results:
                return {
                    "hash": hash_val,
                    "type": "unknown",
                    "possible_types": []
                }
            
            # Get all possible hash types
            possible_types = [result.name for result in results]
            
            # Primary type is the first (most likely)
            primary_type = possible_types[0] if possible_types else "unknown"
            
            return {
                "hash": hash_val,
                "type": primary_type,
                "possible_types": possible_types
            }
        
        except Exception as e:
            return {
                "error": f"Failed to identify hash: {str(e)}"
            }

    def _crack_hash(self, hash_val: str, wordlist: str) -> Dict[str, Any]:
        """Crack hash using hashcat or john.

        Args:
            hash_val: Hash string to crack
            wordlist: Path to wordlist file

        Returns:
            Dict with cracking results
        """
        from src.utils.external_tools import ExternalTool
        
        # Check for hashcat first, then john
        hashcat_version = ExternalTool.detect_tool("hashcat")
        john_version = ExternalTool.detect_tool("john")
        
        if hashcat_version is None and john_version is None:
            return {
                "error": "No cracking tools found. Install with: apt install hashcat (or) apt install john"
            }
        
        # Try hashcat first (faster)
        if hashcat_version:
            return self._crack_with_hashcat(hash_val, wordlist)
        else:
            return self._crack_with_john(hash_val, wordlist)

    def _crack_with_hashcat(self, hash_val: str, wordlist: str) -> Dict[str, Any]:
        """Crack using hashcat."""
        from src.utils.external_tools import ExternalTool
        import tempfile
        import os
        
        # Create temp file for hash
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash') as f:
            f.write(hash_val)
            hash_file = f.name
        
        try:
            # Hashcat command: -m 0 for MD5, -a 0 for dictionary attack
            # This is a simplified version - real implementation would need hash type detection
            cmd = ["hashcat", "-m", "0", "-a", "0", hash_file, wordlist, "--quiet"]
            
            stdout, stderr, exit_code = ExternalTool.run_tool(cmd, timeout=300)  # 5 min timeout
            
            # Parse hashcat output
            if exit_code == 0 and ":" in stdout:
                # Hashcat format: hash:plaintext
                parts = stdout.strip().split(":")
                if len(parts) >= 2:
                    plaintext = parts[-1]
                    return {
                        "hash": hash_val,
                        "cracked": True,
                        "plaintext": plaintext,
                        "tool_used": "hashcat"
                    }
            
            return {
                "hash": hash_val,
                "cracked": False,
                "plaintext": None,
                "tool_used": "hashcat",
                "message": "Hash not cracked (not in wordlist or wrong hash type)"
            }
        
        finally:
            # Clean up temp file
            if os.path.exists(hash_file):
                os.unlink(hash_file)

    def _crack_with_john(self, hash_val: str, wordlist: str) -> Dict[str, Any]:
        """Crack using John the Ripper."""
        from src.utils.external_tools import ExternalTool
        import tempfile
        import os
        
        # Create temp file for hash
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash') as f:
            f.write(hash_val)
            hash_file = f.name
        
        try:
            # John command
            cmd = ["john", f"--wordlist={wordlist}", hash_file, "--format=raw-md5"]
            
            stdout, stderr, exit_code = ExternalTool.run_tool(cmd, timeout=300)  # 5 min timeout
            
            # Parse john output
            combined_output = stdout + "\n" + stderr
            
            # John outputs cracked passwords in various formats
            # Look for common patterns
            for line in combined_output.splitlines():
                if "(" in line and ")" in line:
                    # Format: password (hash)
                    parts = line.split("(")
                    if len(parts) >= 2:
                        plaintext = parts[0].strip()
                        return {
                            "hash": hash_val,
                            "cracked": True,
                            "plaintext": plaintext,
                            "tool_used": "john"
                        }
            
            return {
                "hash": hash_val,
                "cracked": False,
                "plaintext": None,
                "tool_used": "john",
                "message": "Hash not cracked (not in wordlist or wrong hash type)"
            }
        
        finally:
            # Clean up temp file
            if os.path.exists(hash_file):
                os.unlink(hash_file)

    def run(self, params: Dict[str, Any]) -> None:
        """Run hash identification or cracking.

        Expected params:
            {
                'hash': str,  # Hash to identify/crack
                'mode': str,  # 'identify' or 'crack'
                'wordlist': str,  # Path to wordlist (required for crack mode)
            }
        """
        self._validate_params(params)

        hash_val = params["hash"]
        mode = params.get("mode", "identify")

        if mode == "identify":
            self._result = self._identify_hash(hash_val)
        
        elif mode == "crack":
            wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
            self._result = self._crack_hash(hash_val, wordlist)

    def stop(self) -> None:
        """No-op cleanup hook required by BasePlugin interface."""
        pass

    def get_results(self) -> Dict[str, Any]:
        """Return identification/cracking results."""
        return dict(self._result)
