import json
import os

def load_config(config_file="config.json"):
    """Load configuration from a JSON file."""
    if config_file and os.path.exists(config_file):
        with open(config_file, "r") as file:
            return json.load(file)
    return {
        "capture": {"interface": "eth0"},
        "analysis": {"threshold": 10},
        "detection": {"rules": "data/rules/default_rules.json"
    }