# pyright: reportMissingImports=false
from typing import cast, override

from textual.message import Message
from textual.widgets import ListItem

from src.ui.sidebar import ModuleSidebar, PluginSelected


def test_sidebar_instantiation_and_item_count():
    sidebar = ModuleSidebar()
    assert sidebar is not None
    items = list(sidebar.compose())
    assert len(items) == len(sidebar.plugins)


def test_sidebar_emits_plugin_selected_message():
    class TestSidebar(ModuleSidebar):
        def __init__(self) -> None:
            super().__init__()
            self.events: list[object] = []

        @override
        def post_message(self, message: Message) -> bool:
            if isinstance(message, PluginSelected):
                self.events.append(message.plugin_cls)
            return True

    sidebar = TestSidebar()
    items = list(sidebar.compose())
    assert sidebar.plugins
    first_plugin = sidebar.plugins[0]
    first_item = cast(ListItem, items[0])
    sidebar.on_list_view_selected(ModuleSidebar.Selected(sidebar, first_item, 0))

    assert sidebar.events == [first_plugin]
