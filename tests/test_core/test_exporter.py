import json
from pathlib import Path


def test_exporter_writes_session_json(tmp_path: Path) -> None:
    from src.core.session import SessionManager
    from src.core.exporter import SessionExporter

    db_path = tmp_path / "sessions.db"
    out_path = tmp_path / "export.json"

    manager = SessionManager(str(db_path))
    session_id = manager.create_session("export_test")

    # Save two commands
    _ = manager.save_command(
        session_id,
        "toolA",
        "echo hello",
        {"arg": "hello"},
        "hello\n",
        "",
        0,
        0.01,
    )

    _ = manager.save_command(
        session_id,
        "toolB",
        "ls -la",
        {},
        "file1\nfile2\n",
        "",
        0,
        0.02,
    )

    exporter = SessionExporter(manager)
    exporter.export_session_json(session_id, out_path)

    # Verify file exists and is valid JSON
    assert out_path.exists()
    data = json.loads(out_path.read_text(encoding="utf-8"))

    assert "session" in data
    assert "commands" in data
    assert len(data["commands"]) == 2
