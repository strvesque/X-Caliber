def test_content_panel_add_output_appends_text():
    from src.ui.panel import ContentPanel

    panel = ContentPanel()
    panel.add_output("first line")

    assert panel._last_output == "first line"  # pyright: ignore[reportPrivateUsage]


def test_content_panel_add_output_appends_multiple_lines():
    from src.ui.panel import ContentPanel

    panel = ContentPanel()
    panel.add_output("first line")
    panel.add_output("second line")

    assert panel._last_output == "second line"  # pyright: ignore[reportPrivateUsage]
