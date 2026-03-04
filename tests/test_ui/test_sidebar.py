# pyright: reportMissingImports=false
from typing import cast, override

from textual.message import Message
from textual.widgets import ListItem

from src.ui.sidebar import ModuleSelected, ModuleSidebar


def test_sidebar_instantiation_and_item_count():
    sidebar = ModuleSidebar()
    assert sidebar is not None
    items = list(sidebar.compose())
    assert len(items) == len(ModuleSidebar.MODULE_CATEGORIES)


def test_sidebar_emits_module_selected_message():
    class TestSidebar(ModuleSidebar):
        def __init__(self) -> None:
            super().__init__()
            self.events: list[str] = []

        @override
        def post_message(self, message: Message) -> bool:
            if isinstance(message, ModuleSelected):
                self.events.append(message.module_name)
            return True

    sidebar = TestSidebar()
    category = ModuleSidebar.MODULE_CATEGORIES[0]
    items = list(sidebar.compose())
    first_item = cast(ListItem, next(item for item in items if item.name == category))
    sidebar.on_list_view_selected(ModuleSidebar.Selected(sidebar, first_item, 0))

    assert sidebar.events == [category]
