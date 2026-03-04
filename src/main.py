"""Entry point for pentest_tui (minimal)."""
import argparse
import sys


def build_parser():
    p = argparse.ArgumentParser(prog="pentest_tui")
    p.add_argument("--session", help="session id to load", required=False)
    p.add_argument("--export", help="export session to file", required=False)
    p.add_argument("--list-plugins", action="store_true", help="List available plugins")
    p.add_argument("--check-tools", action="store_true", help="Check required external tools")
    return p


def main(argv=None):
    argv = argv or sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_plugins:
        print("No plugins installed")
    if args.check_tools:
        print("Tool check: OK (stub)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
