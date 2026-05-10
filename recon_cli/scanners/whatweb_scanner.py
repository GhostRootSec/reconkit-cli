"""WhatWeb scanner — web technology fingerprinting."""
import asyncio
import json
from typing import Optional
from recon_cli.scanner_base import ScannerBase, ScanResult

class WhatWebScanner(ScannerBase):
    @classmethod
    def info(cls) -> dict:
        return {
            "name": "whatweb",
            "description": "Web technology fingerprinting (CMS, frameworks, server)",
            "api_key_required": False,
            "speed": "fast",
        }

    async def scan(self, target: str, config: dict) -> ScanResult:
        result = ScanResult(
            scanner_name="WhatWeb",
            target=target,
            success=False,
        )

        timeout = config.get("scan_timeout", 300)

        # Check if whatweb exists
        import shutil
        if not shutil.which("whatweb"):
            result.errors.append("whatweb not found in PATH")
            return result

        cmd = ["whatweb", "-a", "3", "--log-json=-", target]
        stdout, stderr, rc = self.run_command(cmd, timeout=timeout)

        result.raw_output = stdout

        if rc == 0:
            try:
                result.success = True
                parsed = json.loads(stdout.strip())
                if isinstance(parsed, list):
                    result.parsed_data = {"targets": parsed}
                else:
                    result.parsed_data = {"targets": [parsed]}
            except (json.JSONDecodeError, ValueError):
                # Fallback to text parse
                result.success = True
                result.parsed_data = {"raw_text": stdout[:5000]}
        else:
            result.errors.append(f"whatweb exited with code {rc}: {stderr}")

        return result
