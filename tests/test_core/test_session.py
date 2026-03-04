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
