from flask import Flask, render_template, jsonify, request
from config import Config, setup_logging
from models import db, User, ThreatLog, Device
from datetime import datetime

app = Flask(__name__, template_folder='../templates')
app.config.from_object(Config)

db.init_app(app)
setup_logging(app)

with app.app_context():
    db.create_all()
    app.logger.info("Database initialized.")

# === LANDING PAGE: APA GUIDE (NO LOGIN) ===
@app.route('/')
def index():
    app.logger.info("Landing page (APA Guide) loaded")
    return render_template('apa_guide_static.html')

# === THREAT INTEL DASHBOARD ===
@app.route('/threat_intel')
def threat_intel():
    app.logger.info("Threat Intel page accessed")
    threats = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).limit(10).all()
    return render_template('threat_intel.html', threats=threats)

# === DEVICE MANAGER ===
@app.route('/device_manager')
def device_manager():
    app.logger.info("Device Manager page accessed")
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template('device_manager.html', devices=devices)

# === HEALTH CHECK ===
@app.route('/dashboard')
def dashboard():
    app.logger.info(f"Health check from {request.remote_addr}")
    return jsonify({
        "status": "OK",
        "users": User.query.count(),
        "threats": ThreatLog.query.count(),
        "devices": Device.query.count()
    })

# === ERROR HANDLERS ===
@app.errorhandler(404)
def not_found(e):
    app.logger.error(f"404: {request.url}")
    return "Page not found", 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"500: {str(e)}")
    return "Server error", 500

# === SEED DATA ===
with app.app_context():
    if ThreatLog.query.count() == 0:
        app.logger.info("Seeding threat data")
        # ... (same as before)
    if Device.query.count() == 0:
        app.logger.info("Seeding device data")
        sample_devices = [
            ("Router-01", "192.168.1.1", "00:1A:2B:3C:4D:5E", "online"),
            ("Camera-02", "192.168.1.102", "AA:BB:CC:DD:EE:FF", "offline"),
            ("Sensor-03", "192.168.1.103", "11:22:33:44:55:66", "online")
        ]
        for name, ip, mac, status in sample_devices:
            d = Device(name=name, ip=ip, mac=mac, status=status)
            db.session.add(d)
        db.session.commit()

if __name__ == '__main__':
    print("\n=== NaashonSecureIoT ===")
    print(" * Landing Page: / (APA Guide)")
    print(" * Threat Intel: /threat_intel")
    print(" * Device Manager: /device_manager")
    print(" * Health: /dashboard")
    print(" * LOG FILE: logs/app.log\n")
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])
