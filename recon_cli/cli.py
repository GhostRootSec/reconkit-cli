#!/usr/bin/env python3
"""recon-cli - Automated OSINT reconnaissance pipeline."""
import argparse, os, sys
import asyncio
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from rich.console import Console
from rich.table import Table
import scanners
from scanner_base import ScannerBase
from config import load_config
from runner import ReconRunner
from deps import check_all, print_report, auto_install_python_deps

BANNER = "\n".join([
    "╔══════════════════════════════════════════════╗",
    f"║{'RECON-CLI  v0.1.0  --  OSINT Pipeline'.center(46)}║",
    "╚══════════════════════════════════════════════╝",
])

def print_banner(console):
    console.print(BANNER, style="bold cyan", soft_wrap=False)

def show_scanners(console):
    table = Table(title="Available Scanners", show_lines=True)
    table.add_column("Name", style="bold cyan")
    table.add_column("API Key", justify="center")
    table.add_column("Description")
    table.add_column("Speed", justify="center")
    for s in ScannerBase.__subclasses__():
        i = s.info()
        table.add_row(i["name"], "Y" if i.get("api_key_required") else "N", i.get("description",""), i.get("speed","normal"))
    console.print(table)

def main():
    console = Console()
    print_banner(console)
    missing_sys, missing_py = check_all()
    if missing_sys:
        console.print("\n[bold yellow]WARNING: Missing system tools:[/bold yellow]")
        print_report(missing_sys, [])
    if missing_py:
        auto_install_python_deps()
    parser = argparse.ArgumentParser(description="recon-cli OSINT Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  recon-cli --target example.com\n  recon-cli --list-scanners\n  recon-cli --check-deps")
    parser.add_argument("--target","-t", default=None)
    parser.add_argument("--output","-o", default=None)
    parser.add_argument("--format","-f", choices=["markdown","html","json"], default="markdown")
    parser.add_argument("--shodan", action="store_true")
    parser.add_argument("--aggressive", action="store_true")
    parser.add_argument("--only", default=None)
    parser.add_argument("--config", default=None)
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--list-scanners", action="store_true")
    parser.add_argument("--check-deps", action="store_true")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")
    args = parser.parse_args()
    if args.no_color:
        console = Console(force_terminal=False, force_interactive=False)
    if args.check_deps:
        print_report(missing_sys, missing_py)
        sys.exit(0 if not missing_sys and not missing_py else 1)
    if args.list_scanners:
        show_scanners(console)
        return
    config_path = args.config or os.path.expanduser("~/.recon-cli/config.json")
    config = load_config(config_path)
    if args.output: config["output_dir"] = args.output
    if args.shodan: config["shodan_enabled"] = True
    if args.aggressive: config["aggressive"] = True
    target = (args.target or "").strip()
    if not target:
        console.print("[bold red]Error: Target required. Use --target or -t.[/bold red]")
        sys.exit(1)
    selected = [s.strip().lower() for s in args.only.split(",")] if args.only else None
    runner = ReconRunner(target, config, console, selected_scanners=selected)
    report_path = asyncio.run(runner.run())
    console.print("")
    console.print("[bold green]Report saved to: " + report_path + "[/bold green]")

if __name__ == "__main__":
    main()
