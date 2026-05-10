"""Nmap scanner — port scanning and service detection."""
import asyncio
import xml.etree.ElementTree as ET
from typing import Optional
from recon_cli.scanner_base import ScannerBase, ScanResult

class NmapScanner(ScannerBase):
    @classmethod
    def info(cls) -> dict:
        return {
            "name": "nmap",
            "description": "Port scanning, service detection, and OS fingerprinting",
            "api_key_required": False,
            "speed": "slow",
        }

    async def scan(self, target: str, config: str | dict = None) -> ScanResult:
        if isinstance(config, dict):
            pass
        result = ScanResult(
            scanner_name="nmap",
            target=target,
            success=False,
        )

        conf = config if isinstance(config, dict) else {}
        nmap_args = conf.get("nmap_args", "-sV -sC")
        timeout = conf.get("scan_timeout", 300)

        output_file = f"/tmp/nmap_{target.replace('.', '_')}.xml"
        cmd_str = f"nmap {nmap_args} -oX {output_file} --host-timeout 300s {target} 2>&1"

        # Check if nmap exists
        import shutil
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            result.errors.append("nmap not found in PATH")
            return result

        stdout, stderr, rc = self.run_shell(cmd_str, timeout=timeout)
        result.raw_output = stdout + stderr

        if rc == 0 or rc == 1:  # nmap returns 1 when hosts are up but no ports found
            try:
                tree = ET.parse(output_file)
                root = tree.getroot()
                result.parsed_data = self._parse_xml(root, target)
                result.success = True
            except Exception as e:
                result.parsed_data = {}
                result.success = True  # nmap ran, just couldn't parse XML
        else:
            result.errors.append(f"nmap failed with exit code {rc}")
            # Try fallback: regex parse stdout
            if "open" in stdout:
                result.success = True
                result.parsed_data = {"fallback_output": self._parse_fallback(stdout)}

        return result

    def _parse_xml(self, root, target):
        """Parse Nmap XML output."""
        parsed = {
            "target": target,
            "hosts": [],
        }

        for host in root.findall("host"):
            host_data = {
                "ip": "",
                "hostnames": [],
                "ports": [],
                "status": "",
                "os": [],
            }

            status = host.find("status")
            if status is not None:
                host_data["status"] = status.get("state", "")

            addr = host.find("address")
            if addr is not None:
                host_data["ip"] = addr.get("addr", "")

            hostnames = host.find("hostnames")
            if hostnames is not None:
                for name in hostnames.findall("hostname"):
                    host_data["hostnames"].append(name.get("name", ""))

            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    port_data = {
                        "portid": port.get("portid", ""),
                        "protocol": port.get("protocol", ""),
                        "state": "",
                        "service": "",
                        "version": "",
                    }
                    state = port.find("state")
                    if state is not None:
                        port_data["state"] = state.get("state", "")
                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = service.get("name", "")
                        port_data["version"] = service.get("version", "")
                        port_data["product"] = service.get("product", "")

                    host_data["ports"].append(port_data)

            os_info = host.find("os")
            if os_info is not None:
                for match in os_info.findall("osmatch"):
                    host_data["os"].append({
                        "name": match.get("name", ""),
                        "accuracy": match.get("accuracy", ""),
                    })

            parsed["hosts"].append(host_data)

        return parsed

    def _parse_fallback(self, output: str):
        """Fallback regex parsing of nmap text output."""
        import re
        ports = []
        for line in output.split("\n"):
            if "/tcp" in line or "/udp" in line:
                ports.append(line.strip())
        return ports
