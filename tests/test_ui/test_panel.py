def test_content_panel_add_output_appends_text():
    from src.ui.panel import ContentPanel

    panel = ContentPanel()
    panel.add_output("first line")

    assert panel._deferred_renders  # pyright: ignore[reportPrivateUsage]
    assert panel._deferred_renders[-1].content == "first line"  # pyright: ignore[reportPrivateUsage]


def test_content_panel_add_output_appends_multiple_lines():
    from src.ui.panel import ContentPanel

    panel = ContentPanel()
    panel.add_output("first line")
    panel.add_output("second line")

    assert len(panel._deferred_renders) == 2  # pyright: ignore[reportPrivateUsage]
    assert panel._deferred_renders[-1].content == "second line"  # pyright: ignore[reportPrivateUsage]
