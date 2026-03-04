"""Textual application scaffold for Pentest TUI."""
# pyright: reportMissingImports=false

from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import BindingType
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Static

from src.ui.panel import ContentPanel, StatusUpdate
from src.ui.sidebar import ModuleSidebar, PluginSelected


class PentestTUIApp(App[None]):
    """Primary Textual application for the pentesting TUI."""

    BINDINGS: ClassVar[list[BindingType]] = [
        ("q", "quit", "Quit"),
        ("escape", "quit", "Quit"),
        ("tab", "focus_next", "Next panel"),
        ("enter", "run_plugin", "Run"),
        ("r", "run_plugin", "Run"),
    ]
    CSS: ClassVar[str] = """
    Screen {
        background: $surface;
    }

    #layout {
        height: 1fr;
        padding: 1;
    }

    .panel {
        border: solid $accent;
        padding: 1 2;
        background: $panel;
    }

    #sidebar {
        width: 32;
        background: $panel;
        border: solid $primary;
    }

    #main {
        width: 1fr;
        background: $panel;
        border: solid $accent;
    }

    .plugin-item {
        padding: 0 1;
    }

    .plugin-item:hover {
        background: $accent 20%;
    }

    ListView > .listview--cursor {
        background: $accent 40%;
    }

    #panel-title {
        text-style: bold;
        color: $text;
        padding-bottom: 1;
    }

    #panel-description {
        color: $text-muted;
        padding-bottom: 1;
    }

    .section-title {
        text-style: bold;
        color: $accent;
        padding-top: 1;
        padding-bottom: 1;
    }

    #form-fields {
        padding-bottom: 1;
    }

    .field-row {
        height: auto;
        padding-bottom: 1;
    }

    .field-label {
        width: 18;
        color: $text;
    }

    .field-input {
        width: 1fr;
    }

    #form-actions {
        height: auto;
        padding-bottom: 1;
    }

    #results {
        border: round $secondary;
        padding: 1;
        background: $surface;
    }

    #status-bar {
        height: 3;
        padding: 0 1;
        background: $panel;
        border-top: solid $background 50%;
    }

    #status-text {
        color: $text;
    }

    .status-info {
        color: $text;
    }

    .status-running {
        color: $accent;
    }

    .status-error {
        color: $error;
    }
    """

    def compose(self) -> ComposeResult:  # pyright: ignore[reportImplicitOverride]
        yield Header(show_clock=False)
        with Horizontal(id="layout"):
            sidebar = ModuleSidebar()
            sidebar.id = "sidebar"
            sidebar.add_class("panel")
            yield sidebar
            panel = ContentPanel()
            panel.id = "main"
            panel.add_class("panel")
            yield panel
        yield Footer()
        status_bar = Vertical()
        status_bar.id = "status-bar"
        with status_bar:
            status_text = Static("Ready")
            status_text.id = "status-text"
            status_text.add_class("status-info")
            yield status_text
        yield status_bar

    def on_plugin_selected(self, event: PluginSelected) -> None:
        panel = self.query_one(ContentPanel)
        panel.set_plugin(event.plugin_cls)

    def on_status_update(self, event: StatusUpdate) -> None:
        status = self.query_one("#status-text", Static)
        status.update(event.text)
        _ = status.remove_class("status-info", "status-running", "status-error")
        _ = status.add_class(f"status-{event.level}")

    def action_run_plugin(self) -> None:
        panel = self.query_one(ContentPanel)
        panel.run_active_plugin()
