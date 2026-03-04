"""Session management backed by SQLite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any, cast


class SessionManager:
    def __init__(self, db_path: str) -> None:
        self._connection: sqlite3.Connection = sqlite3.connect(db_path)
        self._connection.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        _ = self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                created_at TEXT,
                updated_at TEXT,
                ui_state TEXT
            )
            """
        )
        _ = self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY,
                session_id INTEGER REFERENCES sessions(id),
                module TEXT,
                command TEXT,
                timestamp TEXT,
                params TEXT
            )
            """
        )
        _ = self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS outputs (
                id INTEGER PRIMARY KEY,
                command_id INTEGER REFERENCES commands(id),
                stdout TEXT,
                stderr TEXT,
                exit_code INTEGER,
                duration REAL
            )
            """
        )
        _ = self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS ui_state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                state_json TEXT NOT NULL,
                updated_at TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id)
            )
            """
        )
        _ = self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS module_variables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                module_name TEXT NOT NULL,
                variables_json TEXT NOT NULL,
                updated_at TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(id),
                UNIQUE(session_id, module_name)
            )
            """
        )
        self._connection.commit()

    def create_session(self, name: str) -> int:
        timestamp = self._timestamp()
        cursor = self._connection.execute(
            """
            INSERT INTO sessions (name, created_at, updated_at)
            VALUES (?, ?, ?)
            """,
            (name, timestamp, timestamp),
        )
        self._connection.commit()
        if cursor.lastrowid is None:
            raise RuntimeError("Failed to create session")
        return int(cursor.lastrowid)

    def get_session(self, name: str) -> dict[str, object] | None:
        cursor = self._connection.execute(
            "SELECT * FROM sessions WHERE name = ?",
            (name,),
        )
        row = cast(sqlite3.Row | None, cursor.fetchone())
        if row is None:
            return None
        return dict(row)

    def list_sessions(self) -> list[dict[str, object]]:
        cursor = self._connection.execute("SELECT * FROM sessions ORDER BY id")
        rows = cast(list[sqlite3.Row], cursor.fetchall())
        return [dict(row) for row in rows]

    def save_command(
        self,
        session_id: int,
        module: str,
        command: str,
        params: dict[str, object],
        stdout: str,
        stderr: str = "",
        exit_code: int = 0,
        duration: float = 0.0,
    ) -> int:
        """Save command execution with output. Returns command_id."""
        import json

        timestamp = self._timestamp()
        params_json = json.dumps(params)

        # Insert into commands table
        cmd_cursor = self._connection.execute(
            """
            INSERT INTO commands (session_id, module, command, timestamp, params)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, module, command, timestamp, params_json),
        )

        if cmd_cursor.lastrowid is None:
            raise RuntimeError("Failed to insert command")

        command_id = int(cmd_cursor.lastrowid)

        # Insert into outputs table
        _ = self._connection.execute(
            """
            INSERT INTO outputs (command_id, stdout, stderr, exit_code, duration)
            VALUES (?, ?, ?, ?, ?)
            """,
            (command_id, stdout, stderr, exit_code, duration),
        )

        self._connection.commit()
        return command_id

    def load_commands(self, session_id: int) -> list[dict[str, object]]:
        """Load all commands+outputs for a session."""
        import json

        cursor = self._connection.execute(
            """
            SELECT
                c.id, c.session_id, c.module, c.command, c.timestamp, c.params,
                o.stdout, o.stderr, o.exit_code, o.duration
            FROM commands c
            LEFT JOIN outputs o ON c.id = o.command_id
            WHERE c.session_id = ?
            ORDER BY c.id
            """,
            (session_id,),
        )

        rows = cast(list[sqlite3.Row], cursor.fetchall())
        result = []
        for row in rows:
            row_dict = dict(row)
            # Parse JSON params back to dict
            if row_dict.get("params"):
                row_dict["params"] = json.loads(row_dict["params"])
            result.append(row_dict)

        return result

    def save_ui_state(self, session_id: int, state: dict[str, Any]) -> None:
        """Save UI state (selected module, focus, scroll) to database."""
        import json

        timestamp = self._timestamp()
        state_json = json.dumps(state)

        # Use INSERT OR REPLACE for UPSERT behavior (only one state per session)
        _ = self._connection.execute(
            """
            INSERT OR REPLACE INTO ui_state (id, session_id, state_json, updated_at)
            VALUES (
                (SELECT id FROM ui_state WHERE session_id = ?),
                ?,
                ?,
                ?
            )
            """,
            (session_id, session_id, state_json, timestamp),
        )
        self._connection.commit()

    def load_ui_state(self, session_id: int) -> dict[str, Any] | None:
        """Load UI state from database."""
        import json

        cursor = self._connection.execute(
            """
            SELECT state_json FROM ui_state
            WHERE session_id = ?
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            (session_id,),
        )

        row = cast(sqlite3.Row | None, cursor.fetchone())
        if row is None:
            return None

        state_json = row["state_json"]
        return json.loads(state_json)

    def save_module_variables(
        self, session_id: int, module_name: str, variables: dict[str, Any]
    ) -> None:
        """Save module-specific variables (target IPs, wordlists, etc.)."""
        import json

        timestamp = self._timestamp()
        variables_json = json.dumps(variables)

        # Use INSERT OR REPLACE with UNIQUE constraint (session_id, module_name)
        _ = self._connection.execute(
            """
            INSERT OR REPLACE INTO module_variables (session_id, module_name, variables_json, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (session_id, module_name, variables_json, timestamp),
        )
        self._connection.commit()

    def load_module_variables(
        self, session_id: int, module_name: str
    ) -> dict[str, Any] | None:
        """Load module-specific variables."""
        import json

        cursor = self._connection.execute(
            """
            SELECT variables_json FROM module_variables
            WHERE session_id = ? AND module_name = ?
            """,
            (session_id, module_name),
        )

        row = cast(sqlite3.Row | None, cursor.fetchone())
        if row is None:
            return None

        variables_json = row["variables_json"]
        return json.loads(variables_json)
    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()
