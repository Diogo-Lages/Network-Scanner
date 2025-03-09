import logging
from logging.handlers import RotatingFileHandler
import os
import yaml


class ScannerLogger:
    def __init__(self, config_path="config.yml"):
        self.logger = logging.getLogger("NetworkScanner")
        self.setup_logger(config_path)

    def setup_logger(self, config_path):
        # Load config
        with open(config_path) as f:
            config = yaml.safe_load(f)

        log_config = config["logging"]

        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)

        # Configure logger
        self.logger.setLevel(logging.getLevelName(log_config["level"]))

        # File handler with rotation
        file_handler = RotatingFileHandler(
            f"logs/{log_config['file']}",
            maxBytes=log_config["max_size"],
            backupCount=log_config["backup_count"]
        )

        # Console handler
        console_handler = logging.StreamHandler()

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def info(self, message):
        self.logger.info(message)

    def error(self, message):
        self.logger.error(message)

    def warning(self, message):
        self.logger.warning(message)

    def debug(self, message):
        self.logger.debug(message)

    def critical(self, message):
        self.logger.critical(message)
