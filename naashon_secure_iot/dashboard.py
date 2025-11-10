from flask import Flask
import os

# Simulated config.py
class Config:
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

# Simulated dashboard.py
app = Flask(__name__)
app.config.from_object(Config)

@app.route('/dashboard')
def dashboard():
    return "Dashboard loaded successfully!"

if __name__ == '__main__':
    print("Starting app...")
    app.run(host='0.0.0.0', port=5000, debug=True)
    print("App started on http://localhost:5000/dashboard")
