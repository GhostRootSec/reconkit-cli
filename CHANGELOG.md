# Changelog — Recon-CLI

## [1.0.0] — 2025-05-11

Initial public release.

- Automated OSINT pipeline chaining Nmap, WhatWeb, theHarvester, WPScan, WFuzz, and Shodan
- Accepts bare hostnames, IP addresses, and full URLs as targets
- Consolidated report output in Markdown, HTML, and JSON formats
- Configurable via `~/.recon-cli/config.json`
- Standalone binary — no Python environment required
- Dependency checker (`--check-deps`)
- Scanner listing (`--list-scanners`)
- Rich terminal output with color-coded status indicators
