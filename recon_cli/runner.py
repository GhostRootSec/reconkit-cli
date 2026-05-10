"""Orchestration engine — runs all scanners and collects results."""
import asyncio
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from recon_cli.scanner_base import ScanResult
from recon_cli.scanners.theharvester import TheHarvesterScanner
from recon_cli.scanners.shodan_scanner import ShodanScanner
from recon_cli.scanners.nmap_scanner import NmapScanner
from recon_cli.scanners.whatweb_scanner import WhatWebScanner
from recon_cli.scanners.wpscan_scanner import WPScanScanner
from recon_cli.scanners.wfuzz_scanner import WFuzzScanner
from recon_cli.report import ReportGenerator

# Map of scanner names to classes
SCANNERS = {
    "theharvester": TheHarvesterScanner,
    "shodan": ShodanScanner,
    "nmap": NmapScanner,
    "whatweb": WhatWebScanner,
    "wpscan": WPScanScanner,
    "wfuzz": WFuzzScanner,
}

# Default scanner order (fast → slow)
DEFAULT_ORDER = ["theharvester", "whatweb", "nmap", "wpscan", "wfuzz", "shodan"]

class ReconRunner:
    def __init__(self, target: str, config: dict, console, selected_scanners: Optional[list] = None):
        self.target = target
        self.config = config
        self.console = console
        self.selected = selected_scanners

        # Setup output directory
        output_base = Path(config.get("output_dir", "~/recon-results")).expanduser()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_")
        self.output_dir = output_base / safe_target / timestamp
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.raw_dir = self.output_dir / "raw"
        self.raw_dir.mkdir(exist_ok=True)

        self.results: list[ScanResult] = []

    def get_scanner_order(self) -> list:
        """Get list of scanners to run."""
        if self.selected:
            return [s for s in self.selected if s in SCANNERS]

        scanners = list(DEFAULT_ORDER)

        # Skip Shodan if no API key
        api_key = self.config.get("shodan_api_key", "")
        if not api_key:
            scanners = [s for s in scanners if s != "shodan"]

        # Aggressive mode includes everything, otherwise skip slow ones
        if not self.config.get("aggressive", False):
            scanners = [s for s in scanners if s not in ("wfuzz",)]

        return scanners

    async def run(self) -> str:
        """Run all selected scanners and generate report."""
        self.console.print(f"\n[bold]🎯 Target:[/bold] {self.target}")
        self.console.print(f"[bold]📁 Output:[/bold] {self.output_dir}\n")

        scanner_names = self.get_scanner_order()

        if not scanner_names:
            self.console.print("[yellow]⚠ No scanners available. Check config for API keys.[/yellow]")
            scanner_names = ["theharvester", "whatweb"]  # Always run these

        progress_table = Table(title="Scan Progress")
        progress_table.add_column("Scanner", style="cyan")
        progress_table.add_column("Status", justify="center")
        progress_table.add_column("Findings")

        for name in scanner_names:
            scanner_cls = SCANNERS[name]
            info = scanner_cls.info()

            self.console.print(f"\n[bold blue]▶ Running {info['name']}...[/bold blue]")
            self.console.print(f"  [dim]{info.get('description', '')}[/dim]")

            try:
                scanner = scanner_cls()
                result = await scanner.scan(self.target, self.config)
                self.results.append(result)

                # Save raw output
                raw_file = self.raw_dir / f"{name}.txt"
                raw_file.write_text(result.raw_output or "(no output)")

                if result.success:
                    count = len(result.parsed_data)
                    progress_table.add_row(info["name"], "[green]✅ OK[/green]", f"{count} items")
                    self.console.print(f"  [green]✅ Completed[/green] — saved to raw/{name}.txt")
                else:
                    progress_table.add_row(info["name"], "[red]❌ Failed[/red]", str(result.errors))
                    self.console.print(f"  [red]❌ Failed[/red] — {result.errors}")

            except Exception as e:
                self.console.print(f"  [red]❌ Error: {e}[/red]")
                progress_table.add_row(info["name"], "[red]❌ Error[/red]", str(e))

        # Show summary table
        self.console.print()
        self.console.print(progress_table)

        # Generate report
        self.console.print(f"\n[bold]📝 Generating report...[/bold]")
        report_gen = ReportGenerator(self.target, self.results, self.output_dir, self.console)
        report_path = report_gen.generate(format=self.config.get("report_format", "markdown"))

        return str(report_path)
