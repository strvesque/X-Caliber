"""
RED tests for external tool wrapper framework.
These tests define the expected behavior before implementation.
"""
import subprocess
import time
from unittest.mock import patch, MagicMock


def test_detect_tool_missing():
    """Test that detect_tool returns None for non-existent tools."""
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'utils' / 'external_tools.py'
    spec = importlib.util.spec_from_file_location('external_tools', str(p))
    assert spec is not None, 'Could not load spec for external_tools.py'
    module = importlib.util.module_from_spec(spec)
    loader = getattr(spec, 'loader', None)
    assert loader is not None, 'No loader available for spec'
    loader.exec_module(module)
    
    ExternalTool = module.ExternalTool
    result = ExternalTool.detect_tool('nonexistent_tool_xyz123')
    assert result is None, f'Expected None for missing tool, got {result}'


def test_detect_tool_existing():
    """Test that detect_tool returns version for existing tool (Python)."""
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'utils' / 'external_tools.py'
    spec = importlib.util.spec_from_file_location('external_tools', str(p))
    module = importlib.util.module_from_spec(spec)
    loader = getattr(spec, 'loader', None)
    loader.exec_module(module)
    
    ExternalTool = module.ExternalTool
    result = ExternalTool.detect_tool('python')
    assert result is not None, 'Expected version string for Python, got None'
    assert isinstance(result, str), f'Expected string version, got {type(result)}'
    assert len(result) > 0, 'Expected non-empty version string'


def test_run_tool_success():
    """Test that run_tool executes command and returns output."""
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'utils' / 'external_tools.py'
    spec = importlib.util.spec_from_file_location('external_tools', str(p))
    module = importlib.util.module_from_spec(spec)
    loader = getattr(spec, 'loader', None)
    loader.exec_module(module)
    
    ExternalTool = module.ExternalTool
    stdout, stderr, code = ExternalTool.run_tool(['python', '--version'])
    assert code == 0, f'Expected return code 0, got {code}'
    assert stdout or stderr, 'Expected output in stdout or stderr'


def test_run_tool_timeout():
    """Test that run_tool respects timeout and raises TimeoutExpired."""
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'utils' / 'external_tools.py'
    spec = importlib.util.spec_from_file_location('external_tools', str(p))
    module = importlib.util.module_from_spec(spec)
    loader = getattr(spec, 'loader', None)
    loader.exec_module(module)
    
    ExternalTool = module.ExternalTool
    # Use Python to sleep for 10 seconds with 1 second timeout
    try:
        stdout, stderr, code = ExternalTool.run_tool(['python', '-c', 'import time; time.sleep(10)'], timeout=1)
        # If we get here, timeout didn't work - should return error code or raise
        assert code != 0 or 'timeout' in stderr.lower(), 'Expected timeout to be handled'
    except subprocess.TimeoutExpired:
        # This is acceptable behavior
        pass


def test_run_tool_nonzero_exit():
    """Test that run_tool captures non-zero exit codes."""
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'utils' / 'external_tools.py'
    spec = importlib.util.spec_from_file_location('external_tools', str(p))
    module = importlib.util.module_from_spec(spec)
    loader = getattr(spec, 'loader', None)
    loader.exec_module(module)
    
    ExternalTool = module.ExternalTool
    stdout, stderr, code = ExternalTool.run_tool(['python', '-c', 'import sys; sys.exit(42)'])
    assert code == 42, f'Expected return code 42, got {code}'


def test_parse_version_nmap():
    """Test that parse_version extracts nmap version correctly."""
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'utils' / 'external_tools.py'
    spec = importlib.util.spec_from_file_location('external_tools', str(p))
    module = importlib.util.module_from_spec(spec)
    loader = getattr(spec, 'loader', None)
    loader.exec_module(module)
    
    ExternalTool = module.ExternalTool
    output = "Nmap version 7.93 ( https://nmap.org )"
    version = ExternalTool.parse_version('nmap', output)
    assert version == '7.93', f'Expected "7.93", got "{version}"'


def test_parse_version_hashcat():
    """Test that parse_version extracts hashcat version correctly."""
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'utils' / 'external_tools.py'
    spec = importlib.util.spec_from_file_location('external_tools', str(p))
    module = importlib.util.module_from_spec(spec)
    loader = getattr(spec, 'loader', None)
    loader.exec_module(module)
    
    ExternalTool = module.ExternalTool
    output = "hashcat (v6.2.6) starting..."
    version = ExternalTool.parse_version('hashcat', output)
    assert version == '6.2.6', f'Expected "6.2.6", got "{version}"'


def test_parse_version_john():
    """Test that parse_version extracts john version correctly."""
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'utils' / 'external_tools.py'
    spec = importlib.util.spec_from_file_location('external_tools', str(p))
    module = importlib.util.module_from_spec(spec)
    loader = getattr(spec, 'loader', None)
    loader.exec_module(module)
    
    ExternalTool = module.ExternalTool
    output = "John the Ripper 1.9.0-jumbo-1"
    version = ExternalTool.parse_version('john', output)
    assert version == '1.9.0-jumbo-1', f'Expected "1.9.0-jumbo-1", got "{version}"'


def test_tool_registry_exists():
    """Test that TOOLS registry exists and contains expected tools."""
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / 'src' / 'utils' / 'external_tools.py'
    spec = importlib.util.spec_from_file_location('external_tools', str(p))
    module = importlib.util.module_from_spec(spec)
    loader = getattr(spec, 'loader', None)
    loader.exec_module(module)
    
    assert hasattr(module, 'TOOLS'), 'TOOLS registry not found'
    TOOLS = module.TOOLS
    assert isinstance(TOOLS, dict), 'TOOLS should be a dictionary'
    
    # Check required tools are registered
    required_tools = ['nmap', 'hashcat', 'john', 'sublist3r']
    for tool in required_tools:
        assert tool in TOOLS, f'Tool {tool} not in registry'
        assert 'version_flag' in TOOLS[tool], f'Tool {tool} missing version_flag'
        assert 'version_regex' in TOOLS[tool], f'Tool {tool} missing version_regex'


if __name__ == '__main__':
    # Run all tests
    test_functions = [
        test_detect_tool_missing,
        test_detect_tool_existing,
        test_run_tool_success,
        test_run_tool_timeout,
        test_run_tool_nonzero_exit,
        test_parse_version_nmap,
        test_parse_version_hashcat,
        test_parse_version_john,
        test_tool_registry_exists,
    ]
    
    failed = 0
    for test_func in test_functions:
        try:
            test_func()
            print(f'PASS: {test_func.__name__}')
        except Exception as e:
            print(f'FAIL: {test_func.__name__}: {e}')
            failed += 1
    
    print(f'\n{len(test_functions) - failed}/{len(test_functions)} tests passed')
    if failed > 0:
        exit(1)
