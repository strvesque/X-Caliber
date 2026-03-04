"""Entry point for pentest_tui (minimal)."""
# pyright: reportMissingImports=false
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
    if not argv:
        from src.core.app import PentestTUIApp  # type: ignore[reportMissingImports]

        PentestTUIApp().run()
        return 0
    if args.list_plugins:
        print("No plugins installed")
    if args.check_tools:
        check_external_tools()
        return 0




def check_external_tools():
    """Check availability of external pentesting tools."""
    from src.utils.external_tools import ExternalTool, TOOLS
    
    print("Checking external tools...\n")
    
    all_ok = True
    for tool_name, tool_info in TOOLS.items():
        version = ExternalTool.detect_tool(tool_name)
        
        if version:
            status = "[OK] FOUND"
            version_str = f"(version: {version})"
        else:
            status = "[MISSING] NOT FOUND"
            version_str = ""
            all_ok = False
        
        print(f"{status:12} {tool_name:15} {version_str}")
        
        if not version:
            # Provide install suggestions
            if tool_name == "nmap":
                print(f"             Install: apt install nmap (Linux) or brew install nmap (macOS)")
            elif tool_name == "hashcat":
                print(f"             Install: apt install hashcat (Linux) or brew install hashcat (macOS)")
            elif tool_name == "john":
                print(f"             Install: apt install john (Linux) or brew install john (macOS)")
            elif tool_name == "sublist3r":
                print(f"             Install: pip install sublist3r")
            print()
    
    if all_ok:
        print("\n[OK] All tools are available!")
    else:
        print("\n[WARNING] Some tools are missing. Install them for full functionality.")
if __name__ == "__main__":
    raise SystemExit(main())
