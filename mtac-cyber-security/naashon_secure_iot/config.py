import os
from datetime import timedelta

class Config:
    # Basic Flask Configuration
    SECRET_KEY = os.getenv('SECRET_KEY', 'naashon-mtac-secure-iot-2025')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite3'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

    # Security Configuration
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.getenv('SESSION_LIFETIME_MINUTES', '30')))

    # TLS/SSL Configuration
    SSL_CERT_PATH = os.getenv('SSL_CERT_PATH')
    SSL_KEY_PATH = os.getenv('SSL_KEY_PATH')
    FORCE_HTTPS = os.getenv('FORCE_HTTPS', 'False').lower() == 'true'

    # Authentication & Authorization
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'naashon-jwt-secret-2025')
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRE_MINUTES', '15'))
    JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRE_DAYS', '7'))
    MFA_ENABLED = os.getenv('MFA_ENABLED', 'False').lower() == 'true'
    MFA_ISSUER = os.getenv('MFA_ISSUER', 'NaashonSecureIoT')

    # Encryption Configuration
    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'naashon-encryption-key-2025')
    KEY_ROTATION_DAYS = int(os.getenv('KEY_ROTATION_DAYS', '90'))
    HSM_ENABLED = os.getenv('HSM_ENABLED', 'False').lower() == 'true'
    HSM_MODULE_PATH = os.getenv('HSM_MODULE_PATH')

    # Network Security
    ZERO_TRUST_ENABLED = os.getenv('ZERO_TRUST_ENABLED', 'True').lower() == 'true'
    ACCESS_CONTROL_TIMEOUT = int(os.getenv('ACCESS_CONTROL_TIMEOUT', '3600'))  # seconds
    NETWORK_SEGMENTATION_ENABLED = os.getenv('NETWORK_SEGMENTATION_ENABLED', 'True').lower() == 'true'
    FIREWALL_ENABLED = os.getenv('FIREWALL_ENABLED', 'True').lower() == 'true'
    IDS_ENABLED = os.getenv('IDS_ENABLED', 'False').lower() == 'true'
    VPN_REQUIRED = os.getenv('VPN_REQUIRED', 'False').lower() == 'true'

    # API Security
    API_RATE_LIMIT = int(os.getenv('API_RATE_LIMIT', '100'))  # requests per minute
    API_KEY_REQUIRED = os.getenv('API_KEY_REQUIRED', 'True').lower() == 'true'
    CSRF_PROTECTION_ENABLED = os.getenv('CSRF_PROTECTION_ENABLED', 'True').lower() == 'true'
    INPUT_VALIDATION_STRICT = os.getenv('INPUT_VALIDATION_STRICT', 'True').lower() == 'true'

    # Monitoring & Logging
    LOG_ENCRYPTION_ENABLED = os.getenv('LOG_ENCRYPTION_ENABLED', 'True').lower() == 'true'
    AUDIT_LOG_ENABLED = os.getenv('AUDIT_LOG_ENABLED', 'True').lower() == 'true'
    SIEM_INTEGRATION_ENABLED = os.getenv('SIEM_INTEGRATION_ENABLED', 'False').lower() == 'true'
    ALERTING_ENABLED = os.getenv('ALERTING_ENABLED', 'True').lower() == 'true'

    # Threat Intelligence
    THREAT_INTELLIGENCE_ENABLED = os.getenv('THREAT_INTELLIGENCE_ENABLED', 'True').lower() == 'true'
    THREAT_FEEDS_UPDATE_INTERVAL = int(os.getenv('THREAT_FEEDS_UPDATE_INTERVAL', '3600'))  # seconds
    AUTO_RESPONSE_ENABLED = os.getenv('AUTO_RESPONSE_ENABLED', 'False').lower() == 'true'

    # Compliance
    GDPR_COMPLIANCE_ENABLED = os.getenv('GDPR_COMPLIANCE_ENABLED', 'True').lower() == 'true'
    HIPAA_COMPLIANCE_ENABLED = os.getenv('HIPAA_COMPLIANCE_ENABLED', 'False').lower() == 'true'
    PCI_DSS_COMPLIANCE_ENABLED = os.getenv('PCI_DSS_COMPLIANCE_ENABLED', 'False').lower() == 'true'
    COMPLIANCE_REPORTING_ENABLED = os.getenv('COMPLIANCE_REPORTING_ENABLED', 'True').lower() == 'true'

    # IoT Specific Configuration
    MAX_DEVICES = int(os.getenv('MAX_DEVICES', '1000'))
    ANOMALY_THRESHOLD = float(os.getenv('ANOMALY_THRESHOLD', '0.85'))
    ML_MODEL_PATH = os.getenv('ML_MODEL_PATH', 'models/anomaly_detector.pth')
    FEDERATED_LEARNING_ENABLED = os.getenv('FEDERATED_LEARNING_ENABLED', 'False').lower() == 'true'

    # Network Configuration
    LOCAL_IP = os.getenv('LOCAL_IP', '192.168.1.100')
    SUBNET_MASK = os.getenv('SUBNET_MASK', '255.255.255.0')
    DEFAULT_GATEWAY = os.getenv('DEFAULT_GATEWAY', '192.168.1.1')
    DNS_SUFFIX = os.getenv('DNS_SUFFIX', 'local')

    # MTAC Configuration
    MTAC_NAME = os.getenv('MTAC_NAME', 'MTAC-Secure-IoT-2025')

    def load_from_env(self):
        """Load additional configuration from environment variables."""
        # This method can be extended to load complex configurations
        pass
