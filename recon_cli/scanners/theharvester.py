"""TheHarvester scanner — email/subdomain/host harvesting."""
import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Optional

MODULE_DIR = Path(__file__).resolve().parent.parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from scanner_base import ScannerBase, ScanResult

class TheHarvesterScanner(ScannerBase):
    @classmethod
    def info(cls) -> dict:
        return {
            "name": "theHarvester",
            "description": "Email, subdomain, and host harvesting from public sources",
            "api_key_required": False,
            "speed": "fast",
        }

    async def scan(self, target: str, config: dict) -> ScanResult:
        host_target = self.normalize_host_target(target)
        result = ScanResult(
            scanner_name="theHarvester",
            target=host_target,
            success=False,
        )

        timeout = config.get("scan_timeout", 300)
        cmd = [
            "theHarvester",
            "-d", host_target,
            "-b", "all",
            "-f", "-",  # JSON output to stdout
        ]

        stdout, stderr, rc = self.run_command(cmd, timeout=timeout)

        if rc == 0:
            result.success = True
            result.raw_output = stdout
            result.parsed_data = self._parse(stdout, host_target)
        else:
            result.errors.append(f"theHarvester failed: {stderr}")

        return result

    def _parse(self, output: str, target: str) -> dict:
        """Parse theHarvester JSON output."""
        parsed = {
            "emails": [],
            "hosts": [],
            "subdomains": [],
            "ips": [],
        }
        root_domain = ".".join(target.split(".")[-2:]) if "." in target else target

        try:
            data = json.loads(output)
            for entry in data.get("passive", []) + data.get("resolved", []):
                if "email" in entry.get("type", "").lower():
                    parsed["emails"].append(entry.get("name", ""))
                elif "subdomain" in entry.get("type", "").lower():
                    parsed["subdomains"].append(entry.get("name", ""))
                elif "ip" in entry.get("type", "").lower():
                    parsed["ips"].append(entry.get("name", ""))
                elif "host" in entry.get("type", "").lower():
                    parsed["hosts"].append(entry.get("name", ""))
        except (json.JSONDecodeError, KeyError):
            # Fallback: regex parse
            emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', output)
            domain_pattern = re.escape(root_domain)
            hosts = re.findall(r'(?:^|\s)([a-zA-Z0-9.-]+\.' + domain_pattern + r')', output) if root_domain else []
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', output)
            parsed["emails"] = list(set(emails))
            parsed["hosts"] = list(set(hosts))
            parsed["ips"] = list(set(ips))

        return parsed
