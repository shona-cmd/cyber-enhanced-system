import os
import logging
from logging.handlers import RotatingFileHandler

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-change-in-prod')
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'

    ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', 'oEjkBZoQGZ7qi57R5jsBV-D5Ot122bxk98oXqP5dQmI')

    GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
    GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
    FACEBOOK_CLIENT_ID = os.getenv('FACEBOOK_CLIENT_ID')
    FACEBOOK_CLIENT_SECRET = os.getenv('FACEBOOK_CLIENT_SECRET')

    SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite3'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    @staticmethod
    def validate():
        missing = []
        for var in ('GITHUB_CLIENT_ID', 'GITHUB_CLIENT_SECRET',
                    'FACEBOOK_CLIENT_ID', 'FACEBOOK_CLIENT_SECRET'):
            if not getattr(Config, var):
                missing.append(var)
        if missing:
            raise RuntimeError(f"OAuth config error: Missing: {', '.join(missing)}")

# Setup logging
def setup_logging(app):
    os.makedirs('logs', exist_ok=True)
    handler = RotatingFileHandler('logs/app.log', maxBytes=10000, backupCount=3)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)

Config.validate()
