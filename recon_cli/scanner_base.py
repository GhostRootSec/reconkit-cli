"""Base class for all scanners."""
import subprocess
import shlex
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from pathlib import Path

@dataclass
class ScanResult:
    """Results from a scanner."""
    scanner_name: str
    target: str
    success: bool
    raw_output: str = ""
    parsed_data: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

class ScannerBase(ABC):
    """Abstract base class for all scanners."""

    @classmethod
    @abstractmethod
    def info(cls) -> dict:
        """Return scanner metadata."""
        pass

    @abstractmethod
    async def scan(self, target: str, config: dict) -> ScanResult:
        """Run the scanner against a target."""
        pass

    def run_command(self, cmd: list, timeout: int = 120) -> tuple:
        """Run a shell command and return (stdout, stderr, returncode)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1
        except Exception as e:
            return "", str(e), -1

    def run_shell(self, cmd_str: str, timeout: int = 120) -> tuple:
        """Run a shell command string."""
        try:
            result = subprocess.run(
                cmd_str,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Command timed out", -1
        except Exception as e:
            return "", str(e), -1
