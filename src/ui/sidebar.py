"""Sidebar widget for module navigation."""
from __future__ import annotations

from typing import ClassVar, override

from textual.app import ComposeResult
from textual.message import Message
from textual.widgets import ListItem, ListView, Static


class ModuleSelected(Message):
    """Emitted when a module category is selected."""

    def __init__(self, module_name: str) -> None:
        super().__init__()
        self.module_name: str = module_name


class ModuleSidebar(ListView):
    """ListView-based sidebar for module categories."""

    MODULE_CATEGORIES: ClassVar[tuple[str, ...]] = (
        "Reconnaissance",
        "Web Exploitation",
        "Crypto & Encoding",
        "Network Tools",
        "Exploitation",
    )

    @override
    def compose(self) -> ComposeResult:
        for category in self.MODULE_CATEGORIES:
            yield ListItem(Static(category), name=category)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        module_name = event.item.name
        if module_name is None:
            return
        _ = self.post_message(ModuleSelected(module_name))
