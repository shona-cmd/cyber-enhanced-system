"""
Configuration module for NaashonSecureIoT framework.

Handles MTAC-specific settings for IoT deployments, including thresholds,
device configurations, and security policies.
"""

import os
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
