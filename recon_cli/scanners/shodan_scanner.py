"""Shodan scanner — exposed services & vulnerability lookup."""
import asyncio
import os
from typing import Optional
from recon_cli.scanner_base import ScannerBase, ScanResult

class ShodanScanner(ScannerBase):
    @classmethod
    def info(cls) -> dict:
        return {
            "name": "shodan",
            "description": "Search Shodan for exposed services and CVEs",
            "api_key_required": True,
            "speed": "fast",
        }

    async def scan(self, target: str, config: dict) -> ScanResult:
        result = ScanResult(
            scanner_name="Shodan",
            target=target,
            success=False,
        )

        api_key = config.get("shodan_api_key", os.environ.get("SHODAN_API_KEY", ""))
        if not api_key:
            result.errors.append("Shodan API key not configured. Set SHODAN_API_KEY in config or env.")
            return result

        try:
            import shodan
        except ImportError:
            result.errors.append("shodan Python package not installed. Run: pip install shodan")
            return result

        try:
            api = shodan.Shodan(api_key)
            search_result = api.search(target)

            result.success = True
            result.parsed_data = {
                "total_results": search_result.get("total", 0),
                "matches": [],
            }

            for match in search_result.get("matches", [])[:50]:
                result.parsed_data["matches"].append({
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", 0),
                    "service": match.get("product", ""),
                    "version": match.get("version", ""),
                    "org": match.get("org", ""),
                    "vulns": match.get("vulns", []),
                    "last_seen": match.get("timestamp", ""),
                })

            result.raw_output = str(result.parsed_data)

        except shodan.APIError as e:
            result.errors.append(f"Shodan API error: {e}")

        return result
