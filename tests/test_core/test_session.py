import sqlite3
from pathlib import Path


def test_session_manager_creates_and_fetches_session(tmp_path: Path) -> None:
    from src.core.session import SessionManager

    db_path = tmp_path / "sessions.db"
    manager = SessionManager(str(db_path))

    session_id = manager.create_session("test1")
    assert isinstance(session_id, int)

    session = manager.get_session("test1")
    assert session is not None
    assert session["id"] == session_id
    assert session["name"] == "test1"
    assert session["created_at"] is not None
    assert session["updated_at"] is not None


def test_session_manager_lists_sessions(tmp_path: Path) -> None:
    from src.core.session import SessionManager

    db_path = tmp_path / "sessions.db"
    manager = SessionManager(str(db_path))

    _ = manager.create_session("alpha")
    _ = manager.create_session("beta")

    sessions = manager.list_sessions()
    names = [s["name"] for s in sessions]
    assert "alpha" in names
    assert "beta" in names


def test_session_manager_persists_to_sqlite(tmp_path: Path) -> None:
    from src.core.session import SessionManager

    db_path = tmp_path / "sessions.db"
    manager = SessionManager(str(db_path))

    _ = manager.create_session("test1")

    connection = sqlite3.connect(str(db_path))
    try:
        cursor = connection.execute("SELECT name FROM sessions")
        rows = cursor.fetchall()
    finally:
        connection.close()

    assert ("test1",) in rows


def test_save_and_load_commands(tmp_path: Path) -> None:
    from src.core.session import SessionManager

    db_path = tmp_path / "sessions.db"
    manager = SessionManager(str(db_path))

    session_id = manager.create_session("cmd_test")

    # Save 5 commands with different modules
    cmd1 = manager.save_command(
        session_id, "nmap", "nmap -sV 192.168.1.1", {"target": "192.168.1.1"},
        "PORT 80/tcp open\nPORT 443/tcp open", "", 0, 1.23
    )
    cmd2 = manager.save_command(
        session_id, "gobuster", "gobuster dir -u http://test", {"url": "http://test"},
        "/admin\n/login\n", "", 0, 5.67
    )
    cmd3 = manager.save_command(
        session_id, "sqlmap", "sqlmap -u http://test?id=1", {"url": "http://test?id=1"},
        "Parameter 'id' is vulnerable", "", 0, 12.34
    )
    cmd4 = manager.save_command(
        session_id, "nmap", "nmap -A 10.0.0.1", {"target": "10.0.0.1"},
        "OS: Linux 3.x", "Warning: DNS resolution failed", 1, 8.90
    )
    cmd5 = manager.save_command(
        session_id, "metasploit", "use exploit/multi/handler", {},
        "Exploit loaded", "", 0, 0.45
    )

    assert isinstance(cmd1, int)
    assert isinstance(cmd5, int)

    # Load all commands
    commands = manager.load_commands(session_id)

    # Verify all 5 restored
    assert len(commands) == 5

    # Check first command details
    assert commands[0]["module"] == "nmap"
    assert commands[0]["command"] == "nmap -sV 192.168.1.1"
    assert commands[0]["params"] == {"target": "192.168.1.1"}
    assert "PORT 80/tcp open" in commands[0]["stdout"]
    assert commands[0]["exit_code"] == 0
    assert commands[0]["duration"] == 1.23

    # Check command with stderr
    assert commands[3]["stderr"] == "Warning: DNS resolution failed"
    assert commands[3]["exit_code"] == 1

    # Check all modules present
    modules = [c["module"] for c in commands]
    assert "nmap" in modules
    assert "gobuster" in modules
    assert "sqlmap" in modules
    assert "metasploit" in modules


def test_save_and_load_ui_state(tmp_path: Path) -> None:
    from src.core.session import SessionManager

    db_path = tmp_path / "ui_state.db"
    manager = SessionManager(str(db_path))

    session_id = manager.create_session("ui_state_test")

    # Save UI state
    ui_state = {
        "selected_module": "port_scan",
        "panel_focus": "main_panel",
        "scroll_position": 75,
    }
    manager.save_ui_state(session_id, ui_state)

    # Load UI state
    loaded_state = manager.load_ui_state(session_id)
    assert loaded_state is not None
    assert loaded_state["selected_module"] == "port_scan"
    assert loaded_state["panel_focus"] == "main_panel"
    assert loaded_state["scroll_position"] == 75


def test_ui_state_overwrite(tmp_path: Path) -> None:
    from src.core.session import SessionManager

    db_path = tmp_path / "ui_overwrite.db"
    manager = SessionManager(str(db_path))

    session_id = manager.create_session("overwrite_test")

    # Save initial state
    state_v1 = {"selected_module": "encoder", "scroll_position": 0}
    manager.save_ui_state(session_id, state_v1)

    # Overwrite with new state
    state_v2 = {"selected_module": "port_scan", "scroll_position": 100}
    manager.save_ui_state(session_id, state_v2)

    # Verify only latest state is returned
    loaded = manager.load_ui_state(session_id)
    assert loaded is not None
    assert loaded["selected_module"] == "port_scan"
    assert loaded["scroll_position"] == 100


def test_save_and_load_module_variables(tmp_path: Path) -> None:
    from src.core.session import SessionManager

    db_path = tmp_path / "module_vars.db"
    manager = SessionManager(str(db_path))

    session_id = manager.create_session("module_vars_test")

    # Save variables for port_scan module
    port_scan_vars = {
        "target": "192.168.1.1",
        "ports": "22,80,443",
        "scan_type": "stealth",
    }
    manager.save_module_variables(session_id, "port_scan", port_scan_vars)

    # Save variables for different module
    subdomain_vars = {"domain": "example.com", "engines": "google,bing"}
    manager.save_module_variables(session_id, "subdomain", subdomain_vars)

    # Load port_scan variables
    loaded_port_scan = manager.load_module_variables(session_id, "port_scan")
    assert loaded_port_scan is not None
    assert loaded_port_scan["target"] == "192.168.1.1"
    assert loaded_port_scan["ports"] == "22,80,443"
    assert loaded_port_scan["scan_type"] == "stealth"

    # Load subdomain variables
    loaded_subdomain = manager.load_module_variables(session_id, "subdomain")
    assert loaded_subdomain is not None
    assert loaded_subdomain["domain"] == "example.com"
    assert loaded_subdomain["engines"] == "google,bing"


def test_module_variables_overwrite_per_module(tmp_path: Path) -> None:
    from src.core.session import SessionManager

    db_path = tmp_path / "module_overwrite.db"
    manager = SessionManager(str(db_path))

    session_id = manager.create_session("module_overwrite")

    # Save initial variables
    vars_v1 = {"target": "10.0.0.1", "ports": "80"}
    manager.save_module_variables(session_id, "port_scan", vars_v1)

    # Overwrite with new variables
    vars_v2 = {"target": "192.168.1.1", "ports": "22,80,443"}
    manager.save_module_variables(session_id, "port_scan", vars_v2)

    # Verify only latest variables are returned
    loaded = manager.load_module_variables(session_id, "port_scan")
    assert loaded is not None
    assert loaded["target"] == "192.168.1.1"
    assert loaded["ports"] == "22,80,443"


def test_load_nonexistent_state(tmp_path: Path) -> None:
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
