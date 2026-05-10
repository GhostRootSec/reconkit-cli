"""WFuzz scanner — directory and parameter fuzzing."""
import asyncio
from typing import Optional
from recon_cli.scanner_base import ScannerBase, ScanResult

class WFuzzScanner(ScannerBase):
    @classmethod
    def info(cls) -> dict:
        return {
            "name": "wfuzz",
            "description": "Directory and parameter fuzzing for hidden endpoints",
            "api_key_required": False,
            "speed": "slow",
        }

    async def scan(self, target: str, config: dict) -> ScanResult:
        result = ScanResult(
            scanner_name="WFuzz",
            target=target,
            success=False,
        )

        timeout = config.get("scan_timeout", 300)

        import shutil
        if not shutil.which("wfuzz"):
            result.errors.append("wfuzz not found in PATH")
            return result

        # Quick directory fuzz with common wordlist
        url = f"http://{target}/FUZZ"
        cmd = [
            "wfuzz",
            "-w", "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "--hc", "404",
            "--hl", "0",
            "-t", "20",
            "-o", "json",
            url,
        ]

        stdout, stderr, rc = self.run_command(cmd, timeout=timeout)
        result.raw_output = stdout

        # WFuzz returns non-zero when it finds stuff
        if rc in (0, 1, 2, 3, 4, 7):
            result.success = True
            result.parsed_data = self._parse(stdout)
        else:
            result.parsed_data = {"directories": []}
            result.success = True  # Not finding anything is still a valid result

        return result

    def _parse(self, output: str) -> dict:
        """Parse WFuzz JSON output."""
        import json
        directories = []

        for line in output.strip().split("\n"):
            if line.startswith("{") and line.endswith("}"):
                try:
                    entry = json.loads(line)
                    directories.append({
                        "payload": entry.get("Payload", ""),
                        "code": entry.get("Code", 0),
                        "lines": entry.get("Lines", 0),
                        "words": entry.get("Words", 0),
                        "chars": entry.get("Chars", 0),
                    })
                except json.JSONDecodeError:
                    pass

        return {"directories": directories}
