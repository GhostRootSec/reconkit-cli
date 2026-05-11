"""Dependency checker — ensures all required tools and packages are available."""
import shutil
import subprocess
import sys
from typing import List, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# System commands the tool relies on
SYSTEM_DEPS = {
    "nmap": "nmap",
    "whatweb": "whatweb",
    "theHarvester": "theharvester",
    "wpscan": "wpscan",
    "wfuzz": "wfuzz",
}

# Python packages (module_name: pip_package_name)
PYTHON_DEPS = {
    "rich": "rich",
}


def check_command(cmd: str) -> bool:
    """Check if a system command exists in PATH."""
    return shutil.which(cmd) is not None


def check_python_module(module: str) -> bool:
    """Check if a Python module is importable."""
    try:
        __import__(module)
        return True
    except ImportError:
        return False


def check_all() -> Tuple[List[str], List[str]]:
    """Check all dependencies. Returns (missing_system, missing_python)."""
    missing_system = []
    missing_python = []

    for cmd, name in SYSTEM_DEPS.items():
        if not check_command(cmd):
            missing_system.append(name)

    for mod, pkg in PYTHON_DEPS.items():
        if not check_python_module(mod):
            missing_python.append(pkg)

    return missing_system, missing_python


def print_report(missing_system: List[str], missing_python: List[str]) -> bool:
    """Print dependency report. Returns True if all deps are met."""
    all_ok = not missing_system and not missing_python

    if all_ok:
        console.print(Panel(
            "[bold green]✅ All dependencies satisfied[/bold green]\n"
            "[dim]System tools: nmap, whatweb, theHarvester, wpscan, wfuzz[/dim]\n"
            "[dim]Python packages: rich[/dim]",
            title="recon-cli Dependency Check",
            border_style="green",
        ))
        return True

    console.print(Panel(
        "[bold red]❌ Missing dependencies detected[/bold red]",
        title="recon-cli Dependency Check",
        border_style="red",
    ))

    if missing_system:
        console.print("\n[bold red]Missing system tools:[/bold red]")
        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("Tool", style="cyan")
        table.add_column("Install Command")
        for tool in missing_system:
            table.add_row(tool, f"sudo apt install {tool}")
        console.print(table)

    if missing_python:
        console.print("\n[bold red]Missing Python packages:[/bold red]")
        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("Package", style="cyan")
        table.add_column("Install Command")
        for pkg in missing_python:
            table.add_row(pkg, f"pip install {pkg}")
        console.print(table)

    console.print()
    return False


def auto_install_python_deps():
    """Attempt to auto-install missing Python dependencies."""
    missing = [mod for mod, pkg in PYTHON_DEPS.items() if not check_python_module(mod)]
    if not missing:
        return True

    console.print(f"\n[bold yellow]⬇ Installing: {', '.join(missing)}[/bold yellow]")

    # Detect pip flags
    extra_args = ["--break-system-packages"] if sys.version_info >= (3, 11) else []

    for pkg in missing:
        try:
            cmd = [sys.executable, "-m", "pip", "install", pkg, "--quiet"] + extra_args
            result = subprocess.run(cmd, capture_output=True, timeout=120)
            if check_python_module(pkg):
                console.print(f"  [green]✅ {pkg}[/green]")
            else:
                console.print(f"  [red]❌ {pkg} — try: pip install {pkg}[/red]")
                return False
        except Exception as e:
            console.print(f"  [red]❌ {e}[/red]")
            return False

    console.print("[bold green]Dependencies installed. Restarting...[/bold green]\n")
    return True
