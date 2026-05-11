# recon-cli

A modular, automated OSINT reconnaissance pipeline for domains and IP addresses. Chains multiple scanning tools into a single workflow and generates consolidated reports.

## Features

- Passive and active OSINT via theHarvester, Shodan, Nmap, WhatWeb, WPScan, and WFuzz
- Accepts bare hostnames, IP addresses, or full URLs as targets
- Report output in Markdown, HTML, or JSON
- Configurable via `~/.recon-cli/config.json`
- Runs from source or as a standalone binary (PyInstaller)

## Requirements

### System tools (install via your package manager)

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning and service detection |
| `whatweb` | Web fingerprinting |
| `theHarvester` | Email, host, and subdomain harvesting |
| `wpscan` | WordPress vulnerability scanning |
| `wfuzz` | Web fuzzing and directory brute-force |

```bash
sudo apt install nmap whatweb theharvester wfuzz
# wpscan: gem install wpscan
```

### Python dependencies

```bash
pip install rich
```

## Installation

### Run from source

```bash
git clone <repo-url> ~/recon-cli
cd ~/recon-cli
python -m recon_cli.cli --list-scanners
```

### Build a standalone binary

```bash
cd ~/recon-cli
pyinstaller --onefile --name recon-cli --distpath dist --paths recon_cli recon_cli/cli.py
# Binary is at dist/recon-cli
sudo cp dist/recon-cli /usr/local/bin/recon-cli
```

## Configuration

Create `~/.recon-cli/config.json`:

```json
{
    "shodan_api_key": "YOUR_KEY_HERE",
    "output_dir": "~/recon-results",
    "nmap_args": "-sV -sC",
    "aggressive": false
}
```

A template is provided in `config.json` at the repo root.

## Usage

```
recon-cli --target <TARGET> [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `--target`, `-t` | Target domain, IP, or URL |
| `--only` | Run only specific scanners (comma-separated) |
| `--output`, `-o` | Override output directory |
| `--format`, `-f` | Report format: `markdown` (default), `html`, `json` |
| `--shodan` | Enable Shodan lookup (requires API key) |
| `--aggressive` | Enable aggressive scanning modes |
| `--no-color` | Disable terminal color output |
| `--list-scanners` | Show all available scanners |
| `--check-deps` | Check for required system tools and Python packages |
| `--config` | Path to config file (default: `~/.recon-cli/config.json`) |
| `--version` | Show version |

### Examples

```bash
# Full scan of a domain
recon-cli --target example.com

# Web fingerprinting only
recon-cli --target https://example.com --only whatweb

# Nmap + theHarvester, JSON output
recon-cli --target 192.168.1.1 --only nmap,theharvester --format json

# Check all dependencies
recon-cli --check-deps
```

## Output

Results are saved to `~/recon-results/<target>/<timestamp>/` by default. Each scanner writes its own output file, and a consolidated report is generated at the end.

## Scanners

| Name | API Key | Speed | Description |
|------|---------|-------|-------------|
| `nmap` | No | Slow | Port scanning, service detection, OS fingerprinting |
| `whatweb` | No | Fast | Web technology fingerprinting |
| `theharvester` | No | Normal | Email, hostname, and subdomain harvesting |
| `wpscan` | No | Normal | WordPress vulnerability scanning |
| `wfuzz` | No | Slow | Web directory and parameter fuzzing |
| `shodan` | Yes | Fast | Passive intelligence from Shodan database |

## Project Structure

```
recon_cli/
├── cli.py            # Entrypoint, argument parsing, banner
├── runner.py         # Orchestrates scanner execution and reporting
├── scanner_base.py   # Abstract base class for all scanners
├── config.py         # Config file loading
├── deps.py           # Dependency checker and auto-installer
├── report.py         # Report generation
└── scanners/
    ├── nmap_scanner.py
    ├── shodan_scanner.py
    ├── theharvester.py
    ├── wfuzz_scanner.py
    ├── whatweb_scanner.py
    └── wpscan_scanner.py
```