"""Tests for hash identifier and cracker plugin."""
from unittest.mock import patch, MagicMock, mock_open
import pytest


def test_hash_plugin_metadata():
    """Test that plugin has correct metadata."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    plugin = HashCrackerPlugin()
    assert plugin.name == "Hash Identifier & Cracker"
    assert plugin.category == "crypto"
    assert plugin.description
    assert plugin.version


def test_hash_validates_params():
    """Test parameter validation."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    plugin = HashCrackerPlugin()
    plugin.init({})
    
    # Missing hash
    with pytest.raises(ValueError, match="Missing required param: hash"):
        plugin.run({})
    
    # Empty hash
    with pytest.raises(ValueError, match="hash must be a non-empty string"):
        plugin.run({"hash": ""})
    
    # Invalid hash type
    with pytest.raises(ValueError, match="hash must be a non-empty string"):
        plugin.run({"hash": 123})
    
    # Invalid mode
    with pytest.raises(ValueError, match="mode must be 'identify' or 'crack'"):
        plugin.run({"hash": "abc123", "mode": "invalid"})


def test_hash_identify_md5():
    """Test MD5 hash identification."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    plugin = HashCrackerPlugin()
    plugin.init({})
    
    # MD5 hash of 'password': 5f4dcc3b5aa765d61d8327deb882cf99
    plugin.run({"hash": "5f4dcc3b5aa765d61d8327deb882cf99", "mode": "identify"})
    
    results = plugin.get_results()
    assert results["hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert "MD" in results["type"]  # MD5 or MD2, both valid
    assert len(results["possible_types"]) > 0


def test_hash_identify_sha256():
    """Test SHA256 hash identification."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    plugin = HashCrackerPlugin()
    plugin.init({})
    
    # SHA256 hash
    sha256_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"  # 'password'
    plugin.run({"hash": sha256_hash, "mode": "identify"})
    
    results = plugin.get_results()
    assert results["hash"] == sha256_hash
    assert "SHA" in results["type"] or "256" in results["type"]


def test_hash_identify_unknown():
    """Test identification of unrecognized hash."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    plugin = HashCrackerPlugin()
    plugin.init({})
    
    # Invalid hash (too short)
    plugin.run({"hash": "abc", "mode": "identify"})
    
    results = plugin.get_results()
    assert results["hash"] == "abc"
    # Should either be unknown or have empty possible_types
    assert results["type"] == "unknown" or len(results["possible_types"]) == 0


@patch("src.utils.external_tools.ExternalTool")
def test_hash_crack_no_tools(mock_external_tool):
    """Test crack mode when no cracking tools are available."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    # Mock no tools found
    mock_external_tool.detect_tool.return_value = None
    
    plugin = HashCrackerPlugin()
    plugin.init({})
    plugin.run({"hash": "5f4dcc3b5aa765d61d8327deb882cf99", "mode": "crack"})
    
    results = plugin.get_results()
    assert "error" in results
    assert "No cracking tools found" in results["error"]
    assert "hashcat" in results["error"] or "john" in results["error"]


@patch("src.utils.external_tools.ExternalTool")
@patch("builtins.open", new_callable=mock_open)
@patch("os.path.exists")
@patch("os.unlink")
@patch("tempfile.NamedTemporaryFile")
def test_hash_crack_with_hashcat_success(mock_temp, mock_unlink, mock_exists, mock_file, mock_external_tool):
    """Test successful hash cracking with hashcat."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    # Mock hashcat available
    mock_external_tool.detect_tool.side_effect = lambda tool: "6.2.5" if tool == "hashcat" else None
    
    # Mock hashcat output: hash:plaintext
    mock_external_tool.run_tool.return_value = ("5f4dcc3b5aa765d61d8327deb882cf99:password\n", "", 0)
    
    # Mock temp file
    mock_temp_file = MagicMock()
    mock_temp_file.name = "/tmp/test.hash"
    mock_temp_file.__enter__.return_value = mock_temp_file
    mock_temp.return_value = mock_temp_file
    
    mock_exists.return_value = True
    
    plugin = HashCrackerPlugin()
    plugin.init({})
    plugin.run({"hash": "5f4dcc3b5aa765d61d8327deb882cf99", "mode": "crack", "wordlist": "/tmp/wordlist.txt"})
    
    results = plugin.get_results()
    assert results["hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
    assert results["cracked"] is True
    assert results["plaintext"] == "password"
    assert results["tool_used"] == "hashcat"


@patch("src.utils.external_tools.ExternalTool")
@patch("builtins.open", new_callable=mock_open)
@patch("os.path.exists")
@patch("os.unlink")
@patch("tempfile.NamedTemporaryFile")
def test_hash_crack_with_hashcat_failure(mock_temp, mock_unlink, mock_exists, mock_file, mock_external_tool):
    """Test hash cracking failure (hash not in wordlist)."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    # Mock hashcat available
    mock_external_tool.detect_tool.side_effect = lambda tool: "6.2.5" if tool == "hashcat" else None
    
    # Mock hashcat output: no crack
    mock_external_tool.run_tool.return_value = ("", "Exhausted\n", 1)
    
    # Mock temp file
    mock_temp_file = MagicMock()
    mock_temp_file.name = "/tmp/test.hash"
    mock_temp_file.__enter__.return_value = mock_temp_file
    mock_temp.return_value = mock_temp_file
    
    mock_exists.return_value = True
    
    plugin = HashCrackerPlugin()
    plugin.init({})
    plugin.run({"hash": "unknownhash123", "mode": "crack"})
    
    results = plugin.get_results()
    assert results["cracked"] is False
    assert results["plaintext"] is None
    assert "tool_used" in results


@patch("src.utils.external_tools.ExternalTool")
@patch("builtins.open", new_callable=mock_open)
@patch("os.path.exists")
@patch("os.unlink")
@patch("tempfile.NamedTemporaryFile")
def test_hash_crack_with_john(mock_temp, mock_unlink, mock_exists, mock_file, mock_external_tool):
    """Test hash cracking with John the Ripper."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    # Mock only john available (no hashcat)
    mock_external_tool.detect_tool.side_effect = lambda tool: "1.9.0" if tool == "john" else None
    
    # Mock john output format: password (hash)
    mock_external_tool.run_tool.return_value = ("password (5f4dcc3b5aa765d61d8327deb882cf99)\n", "", 0)
    
    # Mock temp file
    mock_temp_file = MagicMock()
    mock_temp_file.name = "/tmp/test.hash"
    mock_temp_file.__enter__.return_value = mock_temp_file
    mock_temp.return_value = mock_temp_file
    
    mock_exists.return_value = True
    
    plugin = HashCrackerPlugin()
    plugin.init({})
    plugin.run({"hash": "5f4dcc3b5aa765d61d8327deb882cf99", "mode": "crack"})
    
    results = plugin.get_results()
    assert results["cracked"] is True
    assert results["plaintext"] == "password"
    assert results["tool_used"] == "john"


def test_hash_default_mode_is_identify():
    """Test that default mode is identify."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    plugin = HashCrackerPlugin()
    plugin.init({})
    plugin.run({"hash": "5f4dcc3b5aa765d61d8327deb882cf99"})  # No mode specified
    
    results = plugin.get_results()
    # Should identify, not crack
    assert "type" in results or "possible_types" in results


def test_hash_stop_method():
    """Test stop method (no-op for this plugin)."""
    from src.plugins.crypto.hash import HashCrackerPlugin
    
    plugin = HashCrackerPlugin()
    plugin.stop()  # Should not raise
