"""CTF web challenge solver with ffuf integration.

Provides automated web fuzzing capabilities for CTF challenges:
- Hidden path/file discovery
- Header fuzzing
- Cookie fuzzing
"""
from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CTFWebSolver:
    """Web challenge automation using ffuf for fuzzing."""

    def __init__(self, timeout: float = 300.0) -> None:
        """Initialize web solver.
        
        Args:
            timeout: Maximum time for fuzzing operations (seconds)
        """
        self.timeout = timeout
        self.ffuf_available = None

    async def _check_ffuf(self) -> bool:
        """Check if ffuf is installed."""
        if self.ffuf_available is not None:
            return self.ffuf_available
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "ffuf", "-V",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=5.0)
            self.ffuf_available = (proc.returncode == 0)
        except (FileNotFoundError, asyncio.TimeoutError):
            self.ffuf_available = False
            logger.warning("ffuf not found - install with: go install github.com/ffuf/ffuf@latest")
        
        return self.ffuf_available

    async def discover_paths(
        self,
        target_url: str,
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Discover hidden paths using directory/file fuzzing.
        
        Args:
            target_url: Base URL to fuzz (must contain FUZZ keyword or will append /FUZZ)
            wordlist: Path to wordlist file (default: built-in common paths)
            extensions: File extensions to try (e.g., ['.php', '.html'])
        
        Returns:
            Dictionary with discovered paths, status codes, sizes
        """
        if not await self._check_ffuf():
            return {
                "found_paths": [],
                "error": "ffuf not installed",
                "status": "tool_missing"
            }
        
        # Ensure URL has FUZZ keyword
        if "FUZZ" not in target_url:
            target_url = target_url.rstrip("/") + "/FUZZ"
        
        # Use default wordlist if none provided
        if wordlist is None:
            wordlist = self._get_default_wordlist()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            output_file = tmp.name
        
        try:
            cmd = [
                "ffuf",
                "-u", target_url,
                "-w", wordlist,
                "-o", output_file,
                "-of", "json",
                "-t", "10",  # 10 threads
                "-timeout", "10",  # 10s per request
                "-mc", "200,201,202,203,204,301,302,307,308,401,403"  # Match interesting codes
            ]
            
            if extensions:
                cmd.extend(["-e", ",".join(extensions)])
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                proc.kill()
                return {
                    "found_paths": [],
                    "error": "fuzzing timeout",
                    "status": "timeout"
                }
            
            # Parse JSON output
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            results = data.get("results", [])
            found_paths = [
                {
                    "url": r.get("url"),
                    "status": r.get("status"),
                    "length": r.get("length"),
                    "words": r.get("words")
                }
                for r in results
            ]
            
            return {
                "found_paths": found_paths,
                "count": len(found_paths),
                "status": "success"
            }
        
        except Exception as e:
            logger.error(f"Path discovery failed: {e}")
            return {
                "found_paths": [],
                "error": str(e),
                "status": "error"
            }
        finally:
            Path(output_file).unlink(missing_ok=True)

    async def fuzz_headers(
        self,
        target_url: str,
        header_name: str,
        wordlist: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fuzz HTTP headers to find valid values.
        
        Args:
            target_url: Target URL
            header_name: Header to fuzz (e.g., 'X-Forwarded-For')
            wordlist: Path to wordlist for header values
        
        Returns:
            Dictionary with successful header values and responses
        """
        if not await self._check_ffuf():
            return {
                "successful_values": [],
                "error": "ffuf not installed",
                "status": "tool_missing"
            }
        
        if wordlist is None:
            wordlist = self._get_default_wordlist()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            output_file = tmp.name
        
        try:
            cmd = [
                "ffuf",
                "-u", target_url,
                "-H", f"{header_name}: FUZZ",
                "-w", wordlist,
                "-o", output_file,
                "-of", "json",
                "-t", "10",
                "-timeout", "10",
                "-mc", "200,201,202,301,302"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                proc.kill()
                return {
                    "successful_values": [],
                    "error": "fuzzing timeout",
                    "status": "timeout"
                }
            
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            results = data.get("results", [])
            successful = [
                {
                    "value": r.get("input", {}).get("FUZZ"),
                    "status": r.get("status"),
                    "length": r.get("length")
                }
                for r in results
            ]
            
            return {
                "successful_values": successful,
                "count": len(successful),
                "status": "success"
            }
        
        except Exception as e:
            logger.error(f"Header fuzzing failed: {e}")
            return {
                "successful_values": [],
                "error": str(e),
                "status": "error"
            }
        finally:
            Path(output_file).unlink(missing_ok=True)

    async def fuzz_cookies(
        self,
        target_url: str,
        cookie_name: str,
        wordlist: Optional[str] = None
    ) -> Dict[str, Any]:
        """Fuzz cookie values to find valid sessions/tokens.
        
        Args:
            target_url: Target URL
            cookie_name: Cookie name to fuzz
            wordlist: Path to wordlist for cookie values
        
        Returns:
            Dictionary with successful cookie values
        """
        if not await self._check_ffuf():
            return {
                "successful_values": [],
                "error": "ffuf not installed",
                "status": "tool_missing"
            }
        
        if wordlist is None:
            wordlist = self._get_default_wordlist()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            output_file = tmp.name
        
        try:
            cmd = [
                "ffuf",
                "-u", target_url,
                "-b", f"{cookie_name}=FUZZ",
                "-w", wordlist,
                "-o", output_file,
                "-of", "json",
                "-t", "10",
                "-timeout", "10",
                "-mc", "200,201,202,301,302"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            except asyncio.TimeoutError:
                proc.kill()
                return {
                    "successful_values": [],
                    "error": "fuzzing timeout",
                    "status": "timeout"
                }
            
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            results = data.get("results", [])
            successful = [
                {
                    "value": r.get("input", {}).get("FUZZ"),
                    "status": r.get("status"),
                    "length": r.get("length")
                }
                for r in results
            ]
            
            return {
                "successful_values": successful,
                "count": len(successful),
                "status": "success"
            }
        
        except Exception as e:
            logger.error(f"Cookie fuzzing failed: {e}")
            return {
                "successful_values": [],
                "error": str(e),
                "status": "error"
            }
        finally:
            Path(output_file).unlink(missing_ok=True)

    def _get_default_wordlist(self) -> str:
        """Get path to default wordlist (common.txt).
        
        Returns:
            Path to wordlist file (creates minimal one if none exists)
        """
        # Check common locations
        common_paths = [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "wordlists/common.txt"
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        # Create minimal default wordlist
        default_words = [
            "admin", "login", "index", "home", "test",
            "api", "config", "backup", "robots.txt", ".git",
            "dashboard", "panel", "user", "users", "upload"
        ]
        
        tmp = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        tmp.write("\n".join(default_words))
        tmp.close()
        
        logger.info(f"Created minimal wordlist at {tmp.name}")
        return tmp.name
