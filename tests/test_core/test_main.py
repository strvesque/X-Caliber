from src.main import build_parser, main


def test_build_parser_returns_parser():
    p = build_parser()
    assert hasattr(p, "parse_args")


def test_main_runs_and_returns_zero():
    rc = main(["--list-plugins"])
    assert rc == 0


def test_main_list_plugins_and_check_tools_prints(capfd):
    # --list-plugins
    main(["--list-plugins"])
    captured = capfd.readouterr()
    # Should now discover all 5 plugins after TYPE_CHECKING fix
    assert "Found 5 plugin(s)" in captured.out
    assert "Encoder/Decoder" in captured.out
    assert "Port Scanner" in captured.out

    # --check-tools
    main(["--check-tools"])
    captured = capfd.readouterr()
    # Tool check always runs, shows OK or WARNING based on availability
    assert "Checking external tools" in captured.out
