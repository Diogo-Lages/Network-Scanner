import yaml
import os
from .logger import ScannerLogger


class ConfigManager:
    def __init__(self, config_path="config.yml"):
        self.config_path = config_path
        self.logger = ScannerLogger()
        self.config = self.load_config()

    def load_config(self):
        try:
            if not os.path.exists(self.config_path):
                self.logger.error(f"Configuration file not found: {self.config_path}")
                raise FileNotFoundError(f"Configuration file not found: {self.config_path}")

            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)

            self.validate_config(config)
            return config

        except Exception as e:
            self.logger.critical(f"Error loading configuration: {e}")
            raise

    def validate_config(self, config):
        required_sections = ['scanner', 'reporting', 'logging', 'fingerprinting', 'vulnerability']

        for section in required_sections:
            if section not in config:
                raise ValueError(f"Missing required configuration section: {section}")

        # Validate scanner section
        scanner_config = config['scanner']
        if not isinstance(scanner_config.get('default_ports', []), list):
            raise ValueError("scanner.default_ports must be a list")
        if not isinstance(scanner_config.get('timeout', 0), (int, float)):
            raise ValueError("scanner.timeout must be a number")

        # Validate reporting section
        reporting_config = config['reporting']
        if not isinstance(reporting_config.get('formats', []), list):
            raise ValueError("reporting.formats must be a list")

    def get_config(self):
        return self.config

    def update_config(self, new_config):
        try:
            self.validate_config(new_config)

            with open(self.config_path, 'w') as f:
                yaml.dump(new_config, f)

            self.config = new_config
            self.logger.info("Configuration updated successfully")

        except Exception as e:
            self.logger.error(f"Error updating configuration: {e}")
            raise

    def get_scanner_config(self):
        return self.config.get('scanner', {})

    def get_reporting_config(self):
        return self.config.get('reporting', {})

    def get_logging_config(self):
        return self.config.get('logging', {})
