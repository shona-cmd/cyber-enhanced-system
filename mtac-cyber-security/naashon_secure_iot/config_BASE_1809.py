import os

class Config:
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-prod')
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'

    # Encryption (AES-256)
    ENCRYPTION_KEY = os.getenv(
        'ENCRYPTION_KEY',
        'oEjkBZoQGZ7qi57R5jsBV-D5Ot122bxk98oXqP5dQmI'   # fallback for local testing
    )

    # GitHub OAuth
    GITHUB_CLIENT_ID     = os.getenv('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')

    # Facebook OAuth
    FACEBOOK_CLIENT_ID     = os.getenv('FACEBOOK_CLIENT_ID')
    FACEBOOK_CLIENT_SECRET = os.getenv('FACEBOOK_CLIENT_SECRET')

    # Validate required vars at import time (helps catch mis-config early)
    @staticmethod
    def validate():
        missing = []
        for name in ('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
                     'FACEBOOK_CLIENT_ID', 'FACEBOOK_CLIENT_SECRET'):
            if not getattr(Config, name):
                missing.append(name)
        if missing:
            print(f"Warning: Missing env vars: {', '.join(missing)}. Using defaults for development.")

# Run validation when the module is imported
Config.validate()
