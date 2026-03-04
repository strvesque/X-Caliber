# pyright: reportMissingImports=false


def test_textual_app_import_and_instantiation():
    from src.core.app import PentestTUIApp  # type: ignore[reportMissingImports]

    app = PentestTUIApp()
    assert app is not None
