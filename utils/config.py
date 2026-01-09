"""
Jina IDS - Configuration Management
"""

import json
import os
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger("JinaIDS.Config")


DEFAULT_CONFIG = {
    "capture": {
        "interface": "auto",
        "promiscuous": True,
        "buffer_size": 65536,
        "timeout": 1,
        "max_packets": 0,
        "filter": ""
    },
    "analysis": {
        "threshold": 10,
        "packet_buffer": 1000,
        "analysis_interval": 1.0,
        "enable_dpi": True,
        "enable_protocol_analysis": True,
        "rules": "data/rules/default_rules.json"
    },
    "detection": {
        "enable_ml": True,
        "enable_signatures": True,
        "enable_anomaly": True,
        "enable_rate_limiting": True,
        "aggregation_window": 60
    },
    "alerting": {
        "log_file": "data/logs/alerts.log",
        "severity_threshold": "low",
        "enable_notifications": False
    },
    "logging": {
        "level": "INFO",
        "file": "data/logs/ids.log",
        "max_size_mb": 100,
        "backup_count": 5
    },
    "performance": {
        "worker_threads": 4,
        "queue_size": 10000,
        "batch_size": 100
    },
    "threat_intel": {
        "enabled": False,
        "update_interval": 3600,
        "cache_file": "data/threat_intel_cache.json"
    }
}


def load_config(config_file: Optional[str] = "config.json") -> Dict[str, Any]:
    """
    Load configuration from a JSON file.
    
    Args:
        config_file: Path to configuration file. If None, returns defaults.
    
    Returns:
        Configuration dictionary with defaults for missing values
    """
    config = DEFAULT_CONFIG.copy()
    
    if config_file and os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                user_config = json.load(f)
            
            # Deep merge user config with defaults
            config = _deep_merge(config, user_config)
            logger.debug(f"Loaded configuration from {config_file}")
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
    
    return config


def save_config(config: Dict[str, Any], config_file: str = "config.json") -> bool:
    """
    Save configuration to a JSON file.
    
    Args:
        config: Configuration dictionary
        config_file: Path to save configuration
    
    Returns:
        True if saved successfully
    """
    try:
        with open(config_file, "w") as f:
            json.dump(config, f, indent=2)
        logger.info(f"Configuration saved to {config_file}")
        return True
    except Exception as e:
        logger.error(f"Error saving config: {e}")
        return False


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """
    Deep merge two dictionaries.
    
    The override dictionary values take precedence.
    """
    result = base.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    
    return result


def get_default_config() -> Dict[str, Any]:
    """Get a copy of the default configuration."""
    return DEFAULT_CONFIG.copy()


def validate_config(config: Dict[str, Any]) -> tuple:
    """
    Validate a configuration dictionary.
    
    Returns:
        Tuple of (is_valid, list of errors)
    """
    errors = []
    
    # Check required sections
    required_sections = ["capture", "analysis", "detection"]
    for section in required_sections:
        if section not in config:
            errors.append(f"Missing required section: {section}")
    
    # Validate interface
    if "capture" in config:
        interface = config["capture"].get("interface", "")
        if not interface:
            errors.append("Network interface not specified")
    
    # Validate detection settings
    if "detection" in config:
        if "aggregation_window" in config["detection"]:
            window = config["detection"]["aggregation_window"]
            if not isinstance(window, (int, float)) or window < 0:
                errors.append("Invalid aggregation_window value")
    
    return (len(errors) == 0, errors)


class ConfigManager:
    """
    Manager class for handling configuration.
    
    Supports:
    - Loading from file
    - Runtime updates
    - Validation
    - Persistence
    """
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = load_config(config_file)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value using dot notation."""
        keys = key.split(".")
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
        
        return value if value is not None else default
    
    def set(self, key: str, value: Any):
        """Set a configuration value using dot notation."""
        keys = key.split(".")
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def reload(self):
        """Reload configuration from file."""
        self.config = load_config(self.config_file)
    
    def save(self) -> bool:
        """Save current configuration to file."""
        return save_config(self.config, self.config_file)
    
    def validate(self) -> tuple:
        """Validate current configuration."""
        return validate_config(self.config)
    
    def to_dict(self) -> Dict[str, Any]:
        """Get configuration as dictionary."""
        return self.config.copy()


if __name__ == "__main__":
    # Test configuration
    import json
    
    # Test load
    config = load_config(None)
    print("Default config:")
    print(json.dumps(config, indent=2))
    
    # Test ConfigManager
    manager = ConfigManager()
    print(f"\nCapture interface: {manager.get('capture.interface')}")
    print(f"ML enabled: {manager.get('detection.enable_ml')}")
    
    # Test validation
    is_valid, errors = manager.validate()
    print(f"\nConfig valid: {is_valid}")
    if errors:
        print(f"Errors: {errors}")