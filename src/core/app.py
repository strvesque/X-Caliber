"""Textual application scaffold for Pentest TUI."""
# pyright: reportMissingImports=false

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Header, Static


class PentestTUIApp(App):
    """Primary Textual application for the pentesting TUI."""

    TITLE: str = "X-Caliber Pentesting TUI"
    BINDINGS: list[tuple[str, str, str]] = [
        ("q", "quit", "Quit"),
        ("escape", "quit", "Quit"),
        ("tab", "focus_next", "Next panel"),
    ]
    CSS: str = """
    #layout {
        height: 1fr;
    }

    .panel {
        border: solid;
        padding: 1 2;
    }

    #sidebar {
        width: 30%;
    }

    #main {
        width: 70%;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="layout"):
            yield Static("Modules", id="sidebar", classes="panel", can_focus=True)
            yield Static("Content", id="main", classes="panel", can_focus=True)
