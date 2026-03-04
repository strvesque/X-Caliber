from src.main import build_parser, main


def test_build_parser_returns_parser():
    p = build_parser()
    assert hasattr(p, "parse_args")


def test_main_runs_and_returns_zero(monkeypatch):
    # Ensure pytest argv doesn't leak into our app
    import sys

    monkeypatch.setattr(sys, "argv", ["pentest_tui"])
    rc = main(None)
    assert rc == 0


def test_main_list_plugins_and_check_tools_prints(capfd):
    # --list-plugins
    main(["--list-plugins"])
    captured = capfd.readouterr()
    assert "No plugins installed" in captured.out

    # --check-tools
    main(["--check-tools"])
    captured = capfd.readouterr()
    assert "Tool check: OK" in captured.out
