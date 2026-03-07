"""CTF forensics module for file analysis and PCAP parsing.

Provides basic forensics capabilities for CTF challenges:
- File metadata extraction
- File type identification
- PCAP analysis (basic packet inspection)
- String extraction from binary files
"""
from __future__ import annotations

import logging
import mimetypes
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CTFForensics:
    """Basic forensics tools for CTF challenges."""

    def __init__(self) -> None:
        """Initialize forensics module."""
        self.tshark_available = None

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata and basic information from file.
        
        Args:
            file_path: Path to file to analyze
        
        Returns:
            Dictionary with file metadata, type, size, strings
        """
        path = Path(file_path)
        
        if not path.exists():
            return {
                "error": "File not found",
                "path": file_path
            }
        
        result = {
            "path": file_path,
            "name": path.name,
            "size_bytes": path.stat().st_size,
            "modified": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
            "created": datetime.fromtimestamp(path.stat().st_ctime, tz=timezone.utc).isoformat(),
        }
        
        # Detect MIME type
        mime_type, encoding = mimetypes.guess_type(file_path)
        result["mime_type"] = mime_type or "application/octet-stream"
        result["encoding"] = encoding
        
        # Check if file command is available
        try:
            file_output = subprocess.run(
                ["file", "-b", file_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            if file_output.returncode == 0:
                result["file_type"] = file_output.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            result["file_type"] = "unknown (file command not available)"
        
        # Extract readable strings
        try:
            strings = self.extract_strings(file_path, min_length=6, max_count=100)
            result["interesting_strings"] = strings
            result["string_count"] = len(strings)
        except Exception as e:
            logger.warning(f"String extraction failed: {e}")
            result["interesting_strings"] = []
        
        return result

    def extract_strings(
        self,
        file_path: str,
        min_length: int = 4,
        max_count: int = 1000
    ) -> List[str]:
        """Extract printable strings from binary file.
        
        Args:
            file_path: Path to file
            min_length: Minimum string length to extract
            max_count: Maximum number of strings to return
        
        Returns:
            List of extracted strings
        """
        try:
            # Try using strings command if available
            result = subprocess.run(
                ["strings", "-n", str(min_length), file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                strings = result.stdout.strip().split('\n')
                # Filter interesting strings (URLs, flags, emails, etc.)
                interesting = []
                patterns = [
                    r'flag\{[^}]+\}',  # CTF flags
                    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Emails
                    r'https?://[^\s]+',  # URLs
                    r'[A-Z]{3,}_[A-Z_]+',  # Constants
                ]
                
                for s in strings[:max_count]:
                    # Check if string matches interesting patterns
                    for pattern in patterns:
                        if re.search(pattern, s, re.IGNORECASE):
                            interesting.append(s)
                            break
                    else:
                        # Include if it's reasonably long and printable
                        if len(s) >= min_length and s.isprintable():
                            interesting.append(s)
                
                return interesting[:max_count]
        
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Fallback: manual string extraction
            pass
        
        # Manual string extraction
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Extract ASCII strings
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
        
        # Don't forget the last string
        if len(current) >= min_length:
            strings.append(''.join(current))
        
        return strings[:max_count]

    def _check_tshark(self) -> bool:
        """Check if tshark is installed."""
        if self.tshark_available is not None:
            return self.tshark_available
        
        try:
            result = subprocess.run(
                ["tshark", "-v"],
                capture_output=True,
                timeout=5
            )
            self.tshark_available = (result.returncode == 0)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.tshark_available = False
            logger.warning("tshark not found - install Wireshark for PCAP analysis")
        
        return self.tshark_available

    def analyze_pcap(
        self,
        pcap_file: str,
        filter_expr: Optional[str] = None
    ) -> Dict[str, Any]:
        """Analyze PCAP file for interesting packets.
        
        Args:
            pcap_file: Path to PCAP file
            filter_expr: Optional Wireshark display filter (e.g., "http")
        
        Returns:
            Dictionary with packet statistics and extracted data
        """
        if not Path(pcap_file).exists():
            return {
                "error": "PCAP file not found",
                "path": pcap_file
            }
        
        if not self._check_tshark():
            return {
                "error": "tshark not installed",
                "path": pcap_file,
                "install_hint": "apt install tshark (Linux) or brew install wireshark (macOS)"
            }
        
        result = {
            "path": pcap_file,
            "packets": [],
            "http_objects": [],
            "ftp_data": [],
            "telnet_data": []
        }
        
        try:
            # Get packet summary
            cmd = ["tshark", "-r", pcap_file, "-T", "fields", 
                   "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
                   "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "frame.protocols"]
            
            if filter_expr:
                cmd.extend(["-Y", filter_expr])
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                lines = proc.stdout.strip().split('\n')
                for line in lines[:100]:  # Limit to 100 packets
                    fields = line.split('\t')
                    if len(fields) >= 5:
                        result["packets"].append({
                            "number": fields[0],
                            "src_ip": fields[1],
                            "dst_ip": fields[2],
                            "src_port": fields[3],
                            "dst_port": fields[4],
                            "protocols": fields[5] if len(fields) > 5 else ""
                        })
            
            # Extract HTTP objects
            try:
                http_cmd = ["tshark", "-r", pcap_file, "-Y", "http", "-T", "fields",
                            "-e", "http.request.uri", "-e", "http.request.method",
                            "-e", "http.response.code"]
                
                http_proc = subprocess.run(
                    http_cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if http_proc.returncode == 0:
                    for line in http_proc.stdout.strip().split('\n')[:50]:
                        fields = line.split('\t')
                        if len(fields) >= 2 and fields[0]:
                            result["http_objects"].append({
                                "uri": fields[0],
                                "method": fields[1] if len(fields) > 1 else "",
                                "status": fields[2] if len(fields) > 2 else ""
                            })
            
            except subprocess.TimeoutExpired:
                logger.warning("HTTP extraction timed out")
            
            result["packet_count"] = len(result["packets"])
            result["http_count"] = len(result["http_objects"])
            result["status"] = "success"
        
        except subprocess.TimeoutExpired:
            return {
                "error": "PCAP analysis timed out",
                "path": pcap_file
            }
        except Exception as e:
            return {
                "error": str(e),
                "path": pcap_file
            }
        
        return result

    def extract_pcap_plaintext(self, pcap_file: str) -> Dict[str, Any]:
        """Extract plaintext data from PCAP (HTTP, FTP, Telnet).
        
        Args:
            pcap_file: Path to PCAP file
        
        Returns:
            Dictionary with extracted plaintext protocols
        """
        if not self._check_tshark():
            return {
                "error": "tshark not installed",
                "plaintext_data": []
            }
        
        result = {
            "path": pcap_file,
            "plaintext_data": []
        }
        
        try:
            # Extract HTTP data
            cmd = ["tshark", "-r", pcap_file, "-Y", "http", "-T", "fields",
                   "-e", "http.file_data"]
            
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                for line in proc.stdout.strip().split('\n'):
                    if line.strip():
                        # Convert hex to ASCII if needed
                        try:
                            decoded = bytes.fromhex(line.replace(':', '')).decode('utf-8', errors='ignore')
                            if decoded.strip():
                                result["plaintext_data"].append({
                                    "protocol": "HTTP",
                                    "data": decoded[:1000]  # Limit size
                                })
                        except:
                            result["plaintext_data"].append({
                                "protocol": "HTTP",
                                "data": line[:1000]
                            })
            
            result["count"] = len(result["plaintext_data"])
            result["status"] = "success"
        
        except subprocess.TimeoutExpired:
            result["error"] = "Extraction timed out"
        except Exception as e:
            result["error"] = str(e)
        
        return result
