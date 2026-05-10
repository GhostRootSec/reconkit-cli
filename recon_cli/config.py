"""Configuration management for recon-cli."""
import json
import os
from pathlib import Path

DEFAULT_CONFIG = {
    "shodan_api_key": "",
    "output_dir": "~/recon-results",
    "nmap_args": "-sV -sC",
    "aggressive": False,
    "scan_timeout": 300,
    "max_threads": 5,
}

def load_config(config_path=None):
    """Load config from file, merging with defaults."""
    config = DEFAULT_CONFIG.copy()

    if config_path is None:
        config_path = os.path.expanduser("~/.recon-cli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                user_config = json.load(f)
            config.update(user_config)
        except (json.JSONDecodeError, IOError):
            pass

    # Also check environment variables
    if os.environ.get("SHODAN_API_KEY"):
        config["shodan_api_key"] = os.environ["SHODAN_API_KEY"]

    # Expand paths
    config["output_dir"] = os.path.expanduser(config["output_dir"])

    return config
