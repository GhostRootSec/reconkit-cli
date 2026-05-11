"""Entry point for python3 -m recon_cli."""

import sys
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

from cli import main

if __name__ == "__main__":
    main()
