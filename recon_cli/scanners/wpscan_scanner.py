"""WPScan scanner — WordPress vulnerability detection."""
import asyncio
import json
from typing import Optional
from recon_cli.scanner_base import ScannerBase, ScanResult

class WPScanScanner(ScannerBase):
    @classmethod
    def info(cls) -> dict:
        return {
            "name": "wpscan",
            "description": "WordPress vulnerability, plugin, and theme scanner",
            "api_key_required": False,
            "speed": "medium",
        }

    async def scan(self, target: str, config: dict) -> ScanResult:
        result = ScanResult(
            scanner_name="WPScan",
            target=target,
            success=False,
        )

        timeout = config.get("scan_timeout", 300)

        import shutil
        if not shutil.which("wpscan"):
            result.errors.append("wpscan not found in PATH")
            return result

        api_token = config.get("wpscan_api_key", "")
        cmd = ["wpscan", "--url", target, "--format", "json", "--no-banner"]
        if api_token:
            cmd.extend(["--api-token", api_token])

        stdout, stderr, rc = self.run_command(cmd, timeout=timeout)
        result.raw_output = stdout

        # WPScan returns non-zero even on successful scans with findings
        if rc in (0, 1, 2, 3, 4, 5, 6, 7):
            try:
                parsed = json.loads(stdout.strip())
                result.success = True
                result.parsed_data = parsed
            except (json.JSONDecodeError, ValueError):
                result.parsed_data = {"raw_text": stdout[:5000]}
                # Consider it a success if wpscan ran at all
                if "WordPress" in stdout or "version" in stdout.lower():
                    result.success = True
        else:
            result.errors.append(f"wpscan failed: {stderr}")

        return result
