"""Sidebar widget for module navigation."""
from __future__ import annotations

from typing import override

from textual.app import ComposeResult
from textual.message import Message
from textual.widgets import ListItem, ListView, Static

from src.core.plugin import BasePlugin
from src.core.registry import get_registry


class PluginSelected(Message):
    """Emitted when a plugin is selected."""

    def __init__(self, plugin_cls: type[BasePlugin]) -> None:
        super().__init__()
        self.plugin_cls: type[BasePlugin] = plugin_cls


class ModuleSidebar(ListView):
    """ListView-based sidebar for module categories."""

    _plugins: list[type[BasePlugin]] | None = None

    @property
    def plugins(self) -> tuple[type[BasePlugin], ...]:
        plugins = self._plugins or []
        return tuple(plugins)

    @override
    def compose(self) -> ComposeResult:
        plugins = get_registry().discover_plugins()
        self._plugins = list(plugins)
        for plugin_cls in self._plugins:
            label = f"[{plugin_cls.category}] {plugin_cls.name}"
            yield ListItem(Static(label))

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        index = event.index
        plugins = self._plugins or []
        if not (0 <= index < len(plugins)):
            return
        plugin_cls = plugins[index]
        _ = self.post_message(PluginSelected(plugin_cls))
