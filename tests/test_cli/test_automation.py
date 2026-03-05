import importlib

from click.testing import CliRunner


def test_cli_group_loads():
    mod = importlib.import_module("src.cli.automation")
    assert hasattr(mod, "cli")


def test_help_contains_subcommands():
    from src.cli.automation import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])  # group help
    assert result.exit_code == 0
    for cmd in ("auto", "recon", "scan", "exploit", "ctf"):
        assert cmd in result.output


def test_auto_requires_target():
    from src.cli.automation import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["auto"])  # call without required options
    assert result.exit_code != 0
    assert "Missing option '--target'" in result.output


def test_auto_runs_with_target():
    from src.cli.automation import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["auto", "--target", "http://example.com"]) 
    assert result.exit_code == 0
    assert "Starting automation for http://example.com" in result.output


def test_exploit_requires_flag_to_run():
    from src.cli.automation import cli

    runner = CliRunner()
    result = runner.invoke(cli, ["exploit", "--target", "127.0.0.1"]) 
    assert result.exit_code == 0
    assert "Exploit flag not provided" in result.output
