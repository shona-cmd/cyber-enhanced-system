import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-change-in-prod')
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'

    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'oEjkBZoQGZ7qi57R5jsBV-D5Ot122bxk98oXqP5dQmI')

    GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
    FACEBOOK_CLIENT_ID = os.getenv('FACEBOOK_CLIENT_ID')
    FACEBOOK_CLIENT_SECRET = os.getenv('FACEBOOK_CLIENT_SECRET')

    @staticmethod
    def validate():
        missing = []
        for var in ('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
                    'FACEBOOK_CLIENT_ID', 'FACEBOOK_CLIENT_SECRET'):
            if not getattr(Config, var):
                missing.append(var)
        if missing:
            raise RuntimeError(f"OAuth config error: Missing environment variables: {', '.join(missing)}")

# Validate at import time
Config.validate()
