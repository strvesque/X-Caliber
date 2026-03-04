"""Integration test for full state serialization and restoration."""
from pathlib import Path


def test_full_state_save_and_restore(tmp_path: Path) -> None:
    """Test complete state save/restore cycle with UI state and module variables."""
    from src.core.session import SessionManager
    
    db_path = tmp_path / "state_test.db"
    
    # Create session and save state
    manager = SessionManager(str(db_path))
    session_id = manager.create_session("full_state_test")
    
    # Save UI state
    ui_state = {
        "selected_module": "port_scan",
        "panel_focus": "main_panel",
        "scroll_position": 50,
    }
    manager.save_ui_state(session_id, ui_state)
    
    # Save module variables for multiple modules
    port_scan_vars = {
        "target": "192.168.1.1",
        "ports": "22,80,443",
    }
    manager.save_module_variables(session_id, "port_scan", port_scan_vars)
    
    subdomain_vars = {
        "domain": "example.com",
        "engines": "google,bing",
    }
    manager.save_module_variables(session_id, "subdomain", subdomain_vars)
    
    # Close connection (simulate app exit)
    del manager
    
    # Create NEW SessionManager instance (simulate app restart)
    manager_new = SessionManager(str(db_path))
    
    # Load UI state
    loaded_ui_state = manager_new.load_ui_state(session_id)
    assert loaded_ui_state is not None
    assert loaded_ui_state["selected_module"] == "port_scan"
    assert loaded_ui_state["panel_focus"] == "main_panel"
    assert loaded_ui_state["scroll_position"] == 50
    
    # Load module variables for port_scan
    loaded_port_scan_vars = manager_new.load_module_variables(session_id, "port_scan")
    assert loaded_port_scan_vars is not None
    assert loaded_port_scan_vars["target"] == "192.168.1.1"
    assert loaded_port_scan_vars["ports"] == "22,80,443"
    
    # Load module variables for subdomain
    loaded_subdomain_vars = manager_new.load_module_variables(session_id, "subdomain")
    assert loaded_subdomain_vars is not None
    assert loaded_subdomain_vars["domain"] == "example.com"
    assert loaded_subdomain_vars["engines"] == "google,bing"


def test_state_overwrite_on_resave(tmp_path: Path) -> None:
    """Test that UI state is overwritten on subsequent saves."""
    from src.core.session import SessionManager
    
    db_path = tmp_path / "overwrite_test.db"
    manager = SessionManager(str(db_path))
    session_id = manager.create_session("overwrite_test")
    
    # Save initial UI state
    ui_state_v1 = {"selected_module": "encoder", "panel_focus": "sidebar", "scroll_position": 0}
    manager.save_ui_state(session_id, ui_state_v1)
    
    # Overwrite with new state
    ui_state_v2 = {"selected_module": "port_scan", "panel_focus": "main", "scroll_position": 100}
    manager.save_ui_state(session_id, ui_state_v2)
    
    # Load and verify only latest state is kept
    loaded_state = manager.load_ui_state(session_id)
    assert loaded_state is not None
    assert loaded_state["selected_module"] == "port_scan"
    assert loaded_state["panel_focus"] == "main"
    assert loaded_state["scroll_position"] == 100


def test_module_variables_overwrite_per_module(tmp_path: Path) -> None:
    """Test that module variables are overwritten per module on resave."""
    from src.core.session import SessionManager
    
    db_path = tmp_path / "module_overwrite.db"
    manager = SessionManager(str(db_path))
    session_id = manager.create_session("module_overwrite")
    
    # Save initial variables for port_scan
    vars_v1 = {"target": "10.0.0.1", "ports": "80"}
    manager.save_module_variables(session_id, "port_scan", vars_v1)
    
    # Save different module variables (should not interfere)
    encoder_vars = {"input": "test", "algorithm": "base64"}
    manager.save_module_variables(session_id, "encoder", encoder_vars)
    
    # Overwrite port_scan variables
    vars_v2 = {"target": "192.168.1.1", "ports": "22,80,443"}
    manager.save_module_variables(session_id, "port_scan", vars_v2)
    
    # Verify port_scan has new values
    loaded_port_scan = manager.load_module_variables(session_id, "port_scan")
    assert loaded_port_scan is not None
    assert loaded_port_scan["target"] == "192.168.1.1"
    assert loaded_port_scan["ports"] == "22,80,443"
    
    # Verify encoder variables unchanged
    loaded_encoder = manager.load_module_variables(session_id, "encoder")
    assert loaded_encoder is not None
    assert loaded_encoder["input"] == "test"
    assert loaded_encoder["algorithm"] == "base64"


def test_load_nonexistent_state_returns_none(tmp_path: Path) -> None:
    """Test loading state for session that never saved state returns None."""
    from src.core.session import SessionManager
    
    db_path = tmp_path / "nonexistent.db"
    manager = SessionManager(str(db_path))
    session_id = manager.create_session("no_state")
    
    # Try to load UI state without saving first
    loaded_ui = manager.load_ui_state(session_id)
    assert loaded_ui is None
    
    # Try to load module variables without saving first
    loaded_vars = manager.load_module_variables(session_id, "port_scan")
    assert loaded_vars is None


def test_comprehensive_session_restore(tmp_path):
    """Test comprehensive session restore with 5 modules, 20 commands, custom variables.
    
    This is the Task 19 verification test for full state fidelity.
    """
    from src.core.session import SessionManager
    
    db_path = tmp_path / "comprehensive.db"
    manager = SessionManager(str(db_path))
    session_id = manager.create_session("complex_session")
    
    # Save 20 commands across 5 modules
    modules = ["port_scan", "subdomain", "hash", "encoder", "shell_gen"]
    commands_data = []
    
    for i in range(20):
        module = modules[i % 5]
        command = f"command_{i}"
        params = {"param1": f"value_{i}", "param2": i}
        stdout = f"Output for command {i}"
        stderr = f"Error for command {i}" if i % 3 == 0 else ""
        exit_code = 1 if i % 5 == 0 else 0
        duration = 0.5 + (i * 0.1)
        
        cmd_id = manager.save_command(
            session_id, module, command, params,
            stdout, stderr, exit_code, duration
        )
        commands_data.append({
            "id": cmd_id,
            "module": module,
            "command": command,
            "params": params,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "duration": duration
        })
    
    # Save UI state
    ui_state = {
        "selected_module": "port_scan",
        "panel_focus": "main_panel",
        "scroll_position": 75,
        "sidebar_expanded": True,
        "theme": "dark"
    }
    manager.save_ui_state(session_id, ui_state)
    
    # Save module variables for all 5 modules
    module_vars = {
        "port_scan": {
            "target": "10.0.0.1",
            "ports": "1-65535",
            "scan_type": "syn",
            "timeout": 300
        },
        "subdomain": {
            "domain": "hackthebox.com",
            "engines": "google,bing,yahoo",
            "threads": 10
        },
        "hash": {
            "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
            "mode": "crack",
            "wordlist": "/usr/share/wordlists/rockyou.txt"
        },
        "encoder": {
            "input": "admin:password",
            "format": "base64",
            "mode": "encode"
        },
        "shell_gen": {
            "shell_type": "bash",
            "lhost": "10.10.14.5",
            "lport": 4444
        }
    }
    
    for module_name, variables in module_vars.items():
        manager.save_module_variables(session_id, module_name, variables)
    
    # Close and reopen (simulate full app restart)
    del manager
    
    # NEW SESSION - Complete state restore
    manager_restored = SessionManager(str(db_path))
    
    # Verify ALL 20 commands
    loaded_commands = manager_restored.load_commands(session_id)
    assert len(loaded_commands) == 20, f"Expected 20 commands, got {len(loaded_commands)}"
    
    for i, cmd in enumerate(loaded_commands):
        expected = commands_data[i]
        assert cmd["module"] == expected["module"]
        assert cmd["command"] == expected["command"]
        assert cmd["params"]["param1"] == expected["params"]["param1"]
        assert cmd["params"]["param2"] == expected["params"]["param2"]
        assert cmd["stdout"] == expected["stdout"]
        assert cmd["exit_code"] == expected["exit_code"]
    
    # Verify UI state - ALL fields
    loaded_ui = manager_restored.load_ui_state(session_id)
    assert loaded_ui is not None
    assert loaded_ui["selected_module"] == "port_scan"
    assert loaded_ui["panel_focus"] == "main_panel"
    assert loaded_ui["scroll_position"] == 75
    assert loaded_ui["sidebar_expanded"] is True
    assert loaded_ui["theme"] == "dark"
    
    # Verify ALL module variables
    for module_name, expected_vars in module_vars.items():
        loaded_vars = manager_restored.load_module_variables(session_id, module_name)
        assert loaded_vars is not None, f"Module {module_name} vars not loaded"
        
        for key, value in expected_vars.items():
            assert loaded_vars[key] == value, \
                f"Module {module_name}: expected {key}={value}, got {loaded_vars[key]}"
    
    print(f"[OK] Comprehensive restore verified: 20 commands, 5 modules, full UI state")
