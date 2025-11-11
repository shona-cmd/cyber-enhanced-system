"""
Configuration module for NaashonSecureIoT framework.

Handles MTAC-specific settings for IoT deployments, including thresholds,
device configurations, and security policies.
"""

import os
<<<<<<< HEAD
from typing import Dict, Any


class Config:
    """Configuration class for the NaashonSecureIoT framework.

    Handles MTAC-specific settings for IoT deployments, including thresholds,
    device configurations, and security policies.
    """

    def __init__(self):
        # MTAC IoT Environment Settings
        self.mtac_name = "MTAC Cybersecurity Enhancement System"
        self.iot_devices = []  # List of registered IoT devices
        self.max_devices = 1000  # Maximum allowed devices

        # MTAC Network Configuration
        self.local_ip = "10.10.0.141"
        self.subnet_mask = "255.255.252.0"
        self.default_gateway = "10.10.0.1"
        self.dns_suffix = "mtac.ac.ug"

        # Security Thresholds
        self.anomaly_threshold = 0.85  # ML detection threshold
        self.threat_response_efficiency = 0.95  # 95%+ efficiency target
        self.access_control_timeout = 300  # 5 minutes for zero trust

        # Encryption Settings
        self.encryption_algorithm = "AES-256"
        self.key_size = 32  # 256 bits
        self.encryption_key = "YOUR_SECURE_KEY_HERE"

        # Blockchain Settings (simulated)
        self.blockchain_nodes = 5
        self.smart_contract_gas_limit = 2000000

        # Network Settings
        self.mqtt_broker = "10.10.0.1"  # MTAC gateway as MQTT broker
        self.mqtt_port = 8883  # TLS port
        self.zero_trust_enabled = True

        # UGHub Settings
        self.ughub_token_url = "https://iam.ughub.go.ug/token"
        self.ughub_api_base = "https://api.ughub.go.ug"
        self.ughub_client_id = "naashon-secure-iot-app"
        self.ughub_client_secret = "SUPER_SECRET_FROM_UGHUB"

        # AI/ML Settings
        self.ml_model_path = "models/anomaly_detector.pth"
        self.dataset_path = "data/cicids2017_sample.csv"

        # Logging
        self.log_level = "INFO"
        self.log_file = "logs/naashon_secure_iot.log"

        # Flask Settings
        self.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-prod')
        self.debug = os.getenv('FLASK_ENV', 'development') == 'development'

        # GitHub OAuth
        self.github_client_id = os.getenv('GITHUB_CLIENT_ID')
        self.github_client_secret = os.getenv('GITHUB_CLIENT_SECRET')

        # Facebook OAuth
        self.facebook_client_id = os.getenv('FACEBOOK_CLIENT_ID')
        self.facebook_client_secret = os.getenv('FACEBOOK_CLIENT_SECRET')

    def load_from_env(self):
        """Load configuration from environment variables."""
        self.anomaly_threshold = float(
            os.getenv("ANOMALY_THRESHOLD", self.anomaly_threshold))
        self.max_devices = int(os.getenv("MAX_DEVICES", self.max_devices))
        self.zero_trust_enabled = os.getenv(
            "ZERO_TRUST_ENABLED", "true").lower() == "true"

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary for serialization."""
        return {
            "mtac_name": self.mtac_name,
            "max_devices": self.max_devices,
            "anomaly_threshold": self.anomaly_threshold,
            "threat_response_efficiency": self.threat_response_efficiency,
            "encryption_algorithm": self.encryption_algorithm,
            "zero_trust_enabled": self.zero_trust_enabled,
            "mqtt_broker": self.mqtt_broker,
            "mqtt_port": self.mqtt_port,
        }

=======
import logging

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-change-in-prod')
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'

    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'oEjkBZoQGZ7qi57R5jsBV-D5Ot122bxk98oXqP5dQmI')

    GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
    FACEBOOK_CLIENT_ID = os.getenv('FACEBOOK_CLIENT_ID')
    FACEBOOK_CLIENT_SECRET = os.getenv('FACEBOOK_CLIENT_SECRET')

    MQTT_BROKER = os.getenv('MQTT_BROKER')

    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite3'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

>>>>>>> 0be6a386bdf743bca23f23412f15d069d0666896
    @staticmethod
    def validate():
        """Validate required environment variables."""
        missing = []
<<<<<<< HEAD
        for name in ('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
                     'FACEBOOK_CLIENT_ID', 'FACEBOOK_CLIENT_SECRET'):
            if not getattr(Config, name, None):
                missing.append(name)
=======
        for var in ('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
                    'FACEBOOK_CLIENT_ID', 'FACEBOOK_CLIENT_SECRET'):
            if not getattr(Config, var):
                missing.append(var)
<<<<<<< HEAD
>>>>>>> 0be6a386bdf743bca23f23412f15d069d0666896
        if missing:
            raise RuntimeError(f"OAuth config error: Missing: {', '.join(missing)}")
=======
        if missing and Config.DEBUG:
            logging.warning(f"OAuth warning: Missing vars: {', '.join(missing)}. Using fallbacks for dev.")
        elif missing:
            raise RuntimeError(f"OAuth error: Missing vars: {', '.join(missing)}")
>>>>>>> 7e5a1d73660432607a81297dc10002ec6469adb7

# Setup logging
def setup_logging(app):
    os.makedirs('logs', exist_ok=True)
    handler = RotatingFileHandler('logs/app.log', maxBytes=10000, backupCount=3)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)

<<<<<<< HEAD

# Run validation when the module is imported
=======
>>>>>>> 0be6a386bdf743bca23f23412f15d069d0666896
Config.validate()
