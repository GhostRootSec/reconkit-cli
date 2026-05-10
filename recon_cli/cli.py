#!/usr/bin/env python3
"""recon-cli — Automated OSINT reconnaissance pipeline."""
import argparse
import json
import os
import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from recon_cli.config import load_config
from recon_cli.runner import ReconRunner
from recon_cli.deps import check_all, print_report, auto_install_python_deps

console = Console()

BANNER = """
[bold cyan]╔══════════════════════════════════════════════╗
║[/bold cyan][bold red]  ██████╗ ██╗   ██╗███████╗██╗  ██╗[/bold red][bold cyan]        ║
║[/bold cyan][bold red]  ██╔══██╗██║   ██║██╔════╝██║ ██╔╝[/bold red][bold cyan]        ║
║[/bold cyan][bold red]  ██████╔╝██║   ██║█████╗  █████╔╝ [/bold red][bold cyan]   v0.1.0    ║
║[/bold cyan][bold red]  ██╔══██╗██║   ██║██╔══╝  ██╔═██╗ [/bold red][bold cyan]        ║
║[/bold cyan][bold red]  ██████╔╝╚██████╔╝███████╗██║  ██╗[/bold red][bold cyan]        ║
║[/bold cyan][bold red]  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝[/bold red][bold cyan]        ║
║          Automated OSINT Pipeline         ║
╚══════════════════════════════════════════════╝[/bold cyan]
"""

def print_banner():
    console.print(Panel(BANNER, style="bold cyan", border_style="cyan", expand=False))

def main():
    print_banner()

    # Check system deps first
    missing_sys, missing_py = check_all()
    if missing_sys:
        console.print("\n[bold yellow]⚠️  Missing system tools detected.[/bold yellow]")
        print_report(missing_sys, [])
        console.print("[dim]Install them and re-run. Continuing with available scanners...[/dim]\n")

    if missing_py:
        auto_install_python_deps()
        missing_sys2, missing_py2 = check_all()
        if missing_py2:
            console.print("[bold red]❌ Could not install Python dependencies. Fix manually.[/bold red]")

    parser = argparse.ArgumentParser(
        description="recon-cli — Automated OSINT Reconnaissance Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  recon-cli --target example.com
  recon-cli --target example.com --shodan --aggressive
  recon-cli --target example.com --format json -o ~/reports/
  recon-cli --target example.com --only theharvester,nmap
  recon-cli --check-deps
  recon-cli --list-scanners
        """
    )
    parser.add_argument("--target", "-t", default=None, help="Target domain or IP")
    parser.add_argument("--output", "-o", default=None, help="Output directory (default: ~/recon-results)")
    parser.add_argument("--format", "-f", choices=["markdown", "html", "json"], default="markdown", help="Report format")
    parser.add_argument("--shodan", action="store_true", help="Enable Shodan scanning (needs API key)")
    parser.add_argument("--aggressive", action="store_true", help="Enable all scanners including slow ones")
    parser.add_argument("--only", default=None, help="Only run specific scanners (comma-separated)")
    parser.add_argument("--config", default=None, help="Custom config file path")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--list-scanners", action="store_true", help="List available scanners and exit")
    parser.add_argument("--check-deps", action="store_true", help="Check dependencies and exit")
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    args = parser.parse_args()

    if args.no_color:
        console = Console(force_terminal=False, force_interactive=False)

    if args.check_deps:
        _, _ = check_all()
        print_report(missing_sys, missing_py)
        sys.exit(0 if not missing_sys and not missing_py else 1)

    if args.list_scanners:
        show_scanners()
        return

    config_path = args.config or os.path.expanduser("~/.recon-cli/config.json")
    config = load_config(config_path)

    if args.output:
        config["output_dir"] = args.output
    if args.shodan:
        config["shodan_enabled"] = True
    if args.aggressive:
        config["aggressive"] = True

    target = (args.target or "").strip()
    if not target:
        console.print("[bold red]Error: Target required. Use --target or -t.[/bold red]")
        sys.exit(1)

    selected = None
    if args.only:
        selected = [s.strip().lower() for s in args.only.split(",")]

    runner = ReconRunner(target, config, console, selected_scanners=selected)
    report_path = runner.run()
    console.print(f"\n[bold green]✅ Report saved to: {report_path}[/bold green]")

def show_scanners():
    table = Table(title="Available Scanners", show_lines=True)
    table.add_column("Name", style="bold cyan")
    table.add_column("API Key", justify="center")
    table.add_column("Description")
    table.add_column("Speed", justify="center")

    from recon_cli.scanner_base import ScannerBase
    scanners = ScannerBase.__subclasses__()

    for scanner in scanners:
        info = scanner.info()
        table.add_row(
            info["name"],
            "🔑" if info.get("api_key_required") else "✗",
            info.get("description", ""),
            info.get("speed", "normal")
        )

    console.print(table)

if __name__ == "__main__":
    main()
