"""Tests for CTF forensics module."""
import asyncio
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

import pytest

from src.ctf.forensics import CTFForensics


@pytest.fixture
def forensics():
    """Create forensics instance."""
    return CTFForensics()


@pytest.fixture
def sample_file():
    """Create temporary sample file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("Hello World\nCTF{test_flag_123}\nemail@example.com\nhttp://test.com")
        f.flush()
        yield f.name
    
    # Cleanup
    Path(f.name).unlink(missing_ok=True)


@pytest.fixture
def sample_binary():
    """Create temporary binary file with embedded strings."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
        # Binary data with embedded ASCII strings
        data = b'\x00\x01\x02' + b'flag{hidden_secret}' + b'\xff\xfe' + b'CONSTANT_VALUE' + b'\x00'
        f.write(data)
        f.flush()
        yield f.name
    
    # Cleanup
    Path(f.name).unlink(missing_ok=True)


class TestAnalyzeFile:
    """Tests for analyze_file method."""
    
    def test_file_not_found(self, forensics):
        """Test analysis of non-existent file."""
        result = forensics.analyze_file("/nonexistent/file.txt")
        
        assert result["error"] == "File not found"
        assert result["path"] == "/nonexistent/file.txt"
    
    def test_basic_metadata(self, forensics, sample_file):
        """Test extraction of basic file metadata."""
        result = forensics.analyze_file(sample_file)
        
        assert result["path"] == sample_file
        assert result["name"] == Path(sample_file).name
        assert result["size_bytes"] > 0
        assert "modified" in result
        assert "created" in result
        
        # Check ISO 8601 timestamp format
        datetime.fromisoformat(result["modified"])
        datetime.fromisoformat(result["created"])
    
    def test_mime_type_detection(self, forensics, sample_file):
        """Test MIME type detection."""
        result = forensics.analyze_file(sample_file)
        
        # Text file should be detected
        assert result["mime_type"] in ["text/plain", "application/octet-stream"]
    
    def test_file_command_available(self, forensics, sample_file):
        """Test file type detection with 'file' command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "ASCII text"
        
        with patch('subprocess.run', return_value=mock_result):
            result = forensics.analyze_file(sample_file)
        
        assert result["file_type"] == "ASCII text"
    
    def test_file_command_unavailable(self, forensics, sample_file):
        """Test graceful fallback when 'file' command missing."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = forensics.analyze_file(sample_file)
        
        assert "unknown" in result["file_type"].lower()
        assert "not available" in result["file_type"]
    
    def test_string_extraction_integration(self, forensics, sample_file):
        """Test that string extraction is called and results included."""
        result = forensics.analyze_file(sample_file)
        
        assert "interesting_strings" in result
        assert "string_count" in result
        assert isinstance(result["interesting_strings"], list)
        assert result["string_count"] == len(result["interesting_strings"])


class TestExtractStrings:
    """Tests for extract_strings method."""
    
    def test_extract_with_strings_command(self, forensics, sample_file):
        """Test string extraction using 'strings' command."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Hello World\nCTF{test_flag}\nemail@test.com\nhttp://example.com\n"
        
        with patch('subprocess.run', return_value=mock_result):
            strings = forensics.extract_strings(sample_file, min_length=4)
        
        assert len(strings) > 0
        assert any("CTF{" in s for s in strings)  # Flag pattern
    
    def test_strings_command_unavailable_fallback(self, forensics, sample_binary):
        """Test manual extraction when 'strings' command unavailable."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            strings = forensics.extract_strings(sample_binary, min_length=4)
        
        # Should fall back to manual extraction
        assert len(strings) > 0
        # Should find embedded ASCII strings
        assert any("flag" in s.lower() for s in strings)
    
    def test_min_length_filter(self, forensics):
        """Test minimum length filtering."""
        # Create binary with short and long strings
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            data = b'\x00AB\x00ABCDEFGH\x00'
            f.write(data)
            f.flush()
            temp_path = f.name
        
        try:
            with patch('subprocess.run', side_effect=FileNotFoundError):
                strings = forensics.extract_strings(temp_path, min_length=6)
            
            # Only strings >= 6 chars should be included
            assert all(len(s) >= 6 for s in strings)
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_max_count_limit(self, forensics):
        """Test maximum count limiting."""
        mock_result = Mock()
        mock_result.returncode = 0
        # Generate 50 strings
        mock_result.stdout = '\n'.join([f"string_{i}" for i in range(50)])
        
        with patch('subprocess.run', return_value=mock_result):
            strings = forensics.extract_strings("/fake/path", max_count=20)
        
        assert len(strings) <= 20
    
    def test_interesting_pattern_detection(self, forensics):
        """Test detection of interesting patterns (flags, emails, URLs)."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "boring_string_1\n"
            "CTF{hidden_flag}\n"
            "another_boring\n"
            "user@example.com\n"
            "https://secret.com/path\n"
            "SOME_CONSTANT_VALUE\n"
        )
        
        with patch('subprocess.run', return_value=mock_result):
            strings = forensics.extract_strings("/fake/path")
        
        # Interesting patterns should be included
        assert any("CTF{" in s for s in strings)
        assert any("@" in s for s in strings)
        assert any("http" in s for s in strings)
    
    def test_manual_extraction_ascii_only(self, forensics):
        """Test manual extraction only includes printable ASCII."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            # Mix of printable and non-printable
            data = b'Hello\x00\xff\xfeWorld\x01Test'
            f.write(data)
            f.flush()
            temp_path = f.name
        
        try:
            with patch('subprocess.run', side_effect=FileNotFoundError):
                strings = forensics.extract_strings(temp_path, min_length=4)
            
            # Should extract "Hello", "World", "Test"
            assert len(strings) >= 2
            assert all(s.isprintable() for s in strings)
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_strings_timeout(self, forensics):
        """Test timeout handling for strings command."""
        import subprocess
        
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('strings', 10)):
            # Should fall back to manual extraction
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                f.write(b'TestString')
                f.flush()
                temp_path = f.name
            
            try:
                strings = forensics.extract_strings(temp_path, min_length=4)
                # Should get results from manual fallback
                assert isinstance(strings, list)
            finally:
                Path(temp_path).unlink(missing_ok=True)


class TestCheckTshark:
    """Tests for _check_tshark method."""
    
    def test_tshark_available(self, forensics):
        """Test detection when tshark is installed."""
        mock_result = Mock()
        mock_result.returncode = 0
        
        with patch('subprocess.run', return_value=mock_result):
            result = forensics._check_tshark()
        
        assert result is True
        assert forensics.tshark_available is True
    
    def test_tshark_unavailable(self, forensics):
        """Test detection when tshark is not installed."""
        with patch('subprocess.run', side_effect=FileNotFoundError):
            result = forensics._check_tshark()
        
        assert result is False
        assert forensics.tshark_available is False
    
    def test_tshark_cached_result(self, forensics):
        """Test that availability check is cached."""
        forensics.tshark_available = True
        
        # Should not call subprocess.run again
        with patch('subprocess.run', side_effect=Exception("Should not be called")):
            result = forensics._check_tshark()
        
        assert result is True
    
    def test_tshark_timeout(self, forensics):
        """Test timeout handling for tshark check."""
        import subprocess
        
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('tshark', 5)):
            result = forensics._check_tshark()
        
        assert result is False
        assert forensics.tshark_available is False


class TestAnalyzePcap:
    """Tests for analyze_pcap method."""
    
    def test_pcap_file_not_found(self, forensics):
        """Test analysis of non-existent PCAP file."""
        result = forensics.analyze_pcap("/nonexistent/file.pcap")
        
        assert result["error"] == "PCAP file not found"
        assert result["path"] == "/nonexistent/file.pcap"
    
    def test_tshark_not_installed(self, forensics):
        """Test graceful failure when tshark unavailable."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(b'\x00' * 100)  # Fake PCAP data
            f.flush()
            temp_path = f.name
        
        try:
            with patch.object(forensics, '_check_tshark', return_value=False):
                result = forensics.analyze_pcap(temp_path)
            
            assert result["error"] == "tshark not installed"
            assert "install_hint" in result
            assert "apt install" in result["install_hint"]
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_basic_packet_extraction(self, forensics):
        """Test extraction of packet summary."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(b'\x00' * 100)
            f.flush()
            temp_path = f.name
        
        try:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = "1\t192.168.1.1\t192.168.1.2\t443\t80\teth:ip:tcp:http\n"
            
            with patch.object(forensics, '_check_tshark', return_value=True):
                with patch('subprocess.run', return_value=mock_result):
                    result = forensics.analyze_pcap(temp_path)
            
            assert result["status"] == "success"
            assert len(result["packets"]) == 1
            assert result["packets"][0]["src_ip"] == "192.168.1.1"
            assert result["packets"][0]["dst_ip"] == "192.168.1.2"
            assert result["packets"][0]["src_port"] == "443"
            assert result["packets"][0]["dst_port"] == "80"
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_filter_expression(self, forensics):
        """Test PCAP analysis with display filter."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(b'\x00' * 100)
            f.flush()
            temp_path = f.name
        
        try:
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = ""
            
            with patch.object(forensics, '_check_tshark', return_value=True):
                with patch('subprocess.run', return_value=mock_result) as mock_run:
                    result = forensics.analyze_pcap(temp_path, filter_expr="http")
                    
                    # Check that filter was passed to tshark
                    call_args = mock_run.call_args_list[0][0][0]
                    assert "-Y" in call_args
                    assert "http" in call_args
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_http_object_extraction(self, forensics):
        """Test extraction of HTTP objects."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(b'\x00' * 100)
            f.flush()
            temp_path = f.name
        
        try:
            # Mock packet summary call
            packet_mock = Mock()
            packet_mock.returncode = 0
            packet_mock.stdout = ""
            
            # Mock HTTP extraction call
            http_mock = Mock()
            http_mock.returncode = 0
            http_mock.stdout = "/api/login\tGET\t200\n/api/data\tPOST\t404\n"
            
            with patch.object(forensics, '_check_tshark', return_value=True):
                with patch('subprocess.run', side_effect=[packet_mock, http_mock]):
                    result = forensics.analyze_pcap(temp_path)
            
            assert result["status"] == "success"
            assert len(result["http_objects"]) == 2
            assert result["http_objects"][0]["uri"] == "/api/login"
            assert result["http_objects"][0]["method"] == "GET"
            assert result["http_objects"][0]["status"] == "200"
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_packet_count_limit(self, forensics):
        """Test that packet count is limited."""
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(b'\x00' * 100)
            f.flush()
            temp_path = f.name
        
        try:
            # Generate 150 packets
            packets = '\n'.join([f"{i}\t10.0.0.1\t10.0.0.2\t443\t80\tip:tcp" for i in range(150)])
            mock_result = Mock()
            mock_result.returncode = 0
            mock_result.stdout = packets
            
            http_mock = Mock()
            http_mock.returncode = 0
            http_mock.stdout = ""
            
            with patch.object(forensics, '_check_tshark', return_value=True):
                with patch('subprocess.run', side_effect=[mock_result, http_mock]):
                    result = forensics.analyze_pcap(temp_path)
            
            # Should be limited to 100 packets
            assert len(result["packets"]) <= 100
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_pcap_analysis_timeout(self, forensics):
        """Test timeout handling for PCAP analysis."""
        import subprocess
        
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(b'\x00' * 100)
            f.flush()
            temp_path = f.name
        
        try:
            with patch.object(forensics, '_check_tshark', return_value=True):
                with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('tshark', 30)):
                    result = forensics.analyze_pcap(temp_path)
            
            assert "error" in result
            assert "timed out" in result["error"].lower()
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestExtractPcapPlaintext:
    """Tests for extract_pcap_plaintext method."""
    
    def test_tshark_not_installed(self, forensics):
        """Test graceful failure when tshark unavailable."""
        with patch.object(forensics, '_check_tshark', return_value=False):
            result = forensics.extract_pcap_plaintext("/fake/path.pcap")
        
        assert result["error"] == "tshark not installed"
        assert result["plaintext_data"] == []
    
    def test_http_data_extraction(self, forensics):
        """Test extraction of HTTP plaintext data."""
        mock_result = Mock()
        mock_result.returncode = 0
        # Simulate hex-encoded HTTP data
        mock_result.stdout = "48656c6c6f20576f726c64\n"  # "Hello World" in hex
        
        with patch.object(forensics, '_check_tshark', return_value=True):
            with patch('subprocess.run', return_value=mock_result):
                result = forensics.extract_pcap_plaintext("/fake/path.pcap")
        
        assert result["status"] == "success"
        assert len(result["plaintext_data"]) > 0
        assert result["plaintext_data"][0]["protocol"] == "HTTP"
    
    def test_plaintext_size_limit(self, forensics):
        """Test that plaintext data is size-limited."""
        mock_result = Mock()
        mock_result.returncode = 0
        # Long string
        mock_result.stdout = "41" * 2000 + "\n"  # 2000 'A' characters in hex
        
        with patch.object(forensics, '_check_tshark', return_value=True):
            with patch('subprocess.run', return_value=mock_result):
                result = forensics.extract_pcap_plaintext("/fake/path.pcap")
        
        # Each entry should be limited to 1000 chars
        for entry in result["plaintext_data"]:
            assert len(entry["data"]) <= 1000
    
    def test_extraction_timeout(self, forensics):
        """Test timeout handling for plaintext extraction."""
        import subprocess
        
        with patch.object(forensics, '_check_tshark', return_value=True):
            with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('tshark', 30)):
                result = forensics.extract_pcap_plaintext("/fake/path.pcap")
        
        assert "error" in result
        assert "timed out" in result["error"].lower()
    
    def test_hex_decoding_failure(self, forensics):
        """Test graceful handling of hex decoding errors."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "invalid_hex_string\n"
        
        with patch.object(forensics, '_check_tshark', return_value=True):
            with patch('subprocess.run', return_value=mock_result):
                result = forensics.extract_pcap_plaintext("/fake/path.pcap")
        
        # Should still return results, using raw string
        assert result["status"] == "success"
        assert len(result["plaintext_data"]) > 0
