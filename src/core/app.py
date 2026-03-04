"""Textual application scaffold for Pentest TUI."""
# pyright: reportMissingImports=false

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal
from textual.widgets import Header, Static

from src.ui.panel import ContentPanel


class PentestTUIApp(App[None]):
    """Primary Textual application for the pentesting TUI."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("q", "quit", "Quit"),
        ("escape", "quit", "Quit"),
        ("tab", "focus_next", "Next panel"),
    ]
    CSS: ClassVar[str] = """
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

    def compose(self) -> ComposeResult:  # pyright: ignore[reportImplicitOverride]
        yield Header(show_clock=False)
        with Horizontal(id="layout"):
            yield Static("Modules", id="sidebar", classes="panel")
            yield ContentPanel(id="main", classes="panel")
