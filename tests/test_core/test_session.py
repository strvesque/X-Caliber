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
