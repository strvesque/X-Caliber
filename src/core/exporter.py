from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .session import SessionManager


class SessionExporter:
    """Export session data (metadata + commands/outputs) to JSON.

    This is intentionally small: it queries the provided SessionManager for
    session metadata and commands and writes a formatted JSON file.
    """

    def __init__(self, session_manager: SessionManager) -> None:
        self._manager = session_manager

    def export_session_json(self, session_id: int, output_path: str | Path) -> None:
        """Export a session (by id) to output_path as JSON (indent=2).

        The resulting structure is:
        {
            "session": { ... },
            "commands": [ { command, stdout, stderr, ... }, ... ]
        }
        """
        # Find session metadata by id using list_sessions (SessionManager
        # provides get_session by name only). This keeps coupling low.
        sessions = self._manager.list_sessions()
        # session dict values are typed as object; be explicit about id handling
        session = None
        for s in sessions:
            raw_id = s.get("id", -1)
            try:
                if int(str(raw_id)) == int(session_id):
                    session = s
                    break
            except Exception:
                # skip non-convertible ids
                continue
        if session is None:
            raise ValueError(f"Session with id {session_id} not found")

        commands = self._manager.load_commands(session_id)

        payload: dict[str, Any] = {
            "session": session,
            "commands": commands,
        }

        out_path = Path(output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
