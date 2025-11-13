from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from .config import Config, setup_logging
from .models import db, User, ThreatLog, Device
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

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

# === LOGIN ===
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard_page'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('apa_guide.html')

# === REGISTER ===
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'Student')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(name=name, email=email, password_hash=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('apa_guide.html')

# === LOGOUT ===
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# === DASHBOARD PAGE ===
@app.route('/dashboard_page')
def dashboard_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = {'name': session.get('user_name'), 'email': session.get('user_email')}
    device_count = Device.query.count()
    active_threats = ThreatLog.query.filter(ThreatLog.risk.in_(['High', 'Critical'])).count()
    network_anomalies = ThreatLog.query.filter(ThreatLog.type == 'Anomaly').count()
    blockchain_entries = ThreatLog.query.count()  # Placeholder
    cloud_predictions = 42  # Placeholder
    local_ip = "192.168.1.100"  # Placeholder
    default_gateway = "192.168.1.1"  # Placeholder
    dns_suffix = "local"  # Placeholder
    is_admin = session.get('user_email') == 'admin@example.com'  # Placeholder
    return render_template('dashboard.html', user=user, device_count=device_count, active_threats=active_threats,
                           network_anomalies=network_anomalies, blockchain_entries=blockchain_entries,
                           cloud_predictions=cloud_predictions, local_ip=local_ip, default_gateway=default_gateway,
                           dns_suffix=dns_suffix, is_admin=is_admin)

# === THREAT INTEL DASHBOARD ===
@app.route('/threat_intel')
def threat_intel():
    app.logger.info("Threat Intel page accessed")
    threats = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).limit(10).all()
    return render_template('threat_intel.html', threats=threats)

# === THREAT PAGE ===
@app.route('/threat')
def threat():
    threat_data = [
        {'timestamp': '2023-10-01', 'count': 5},
        {'timestamp': '2023-10-02', 'count': 8},
        {'timestamp': '2023-10-03', 'count': 3},
        {'timestamp': '2023-10-04', 'count': 12},
        {'timestamp': '2023-10-05', 'count': 7}
    ]
    return render_template('threat.html', threat_data=threat_data)

# === DEVICE MANAGER ===
@app.route('/device_manager')
def device_manager():
    app.logger.info("Device Manager page accessed")
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template('device_manager.html', devices=devices)

# === DEVICES PAGE ===
@app.route('/devices')
def devices():
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template('devices.html', devices=devices)

# === COMPLIANCE PAGE ===
@app.route('/compliance')
def compliance():
    last_audit = "November 2025"
    next_audit = "May 2026"
    officer = "John Doe"
    email = "compliance@mtac.ac.ug"
    return render_template('compliance.html', last_audit=last_audit, next_audit=next_audit, officer=officer, email=email)

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
        sample_threats = [
            ("192.168.1.100", "IP", "Firewall", "High", datetime.utcnow()),
            ("malware.exe", "File", "Antivirus", "Critical", datetime.utcnow()),
            ("Anomaly", "Behavior", "AI", "Medium", datetime.utcnow())
        ]
        for ioc, typ, source, risk, ts in sample_threats:
            t = ThreatLog(ioc=ioc, type=typ, source=source, risk=risk, timestamp=ts)
            db.session.add(t)
        db.session.commit()
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
    print(" * Login: /login")
    print(" * Register: /register")
    print(" * Dashboard: /dashboard_page")
    print(" * Threat Intel: /threat_intel")
    print(" * Threat: /threat")
    print(" * Device Manager: /device_manager")
    print(" * Devices: /devices")
    print(" * Compliance: /compliance")
    print(" * Health: /dashboard")
    print(" * LOG FILE: logs/app.log\n")
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])
=======
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
from .config import Config, setup_logging
from .models import db, User, ThreatLog, Device
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

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

# === LOGIN ===
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard_page'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('apa_guide.html')

# === REGISTER ===
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'Student')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(name=name, email=email, password_hash=hashed_password, role=role)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('apa_guide.html')

# === LOGOUT ===
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# === DASHBOARD PAGE ===
@app.route('/dashboard_page')
def dashboard_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = {'name': session.get('user_name'), 'email': session.get('user_email')}
    device_count = Device.query.count()
    active_threats = ThreatLog.query.filter(ThreatLog.risk.in_(['High', 'Critical'])).count()
    network_anomalies = ThreatLog.query.filter(ThreatLog.type == 'Anomaly').count()
    blockchain_entries = ThreatLog.query.count()  # Placeholder
    cloud_predictions = 42  # Placeholder
    local_ip = "192.168.1.100"  # Placeholder
    default_gateway = "192.168.1.1"  # Placeholder
    dns_suffix = "local"  # Placeholder
    is_admin = session.get('user_email') == 'admin@example.com'  # Placeholder
    return render_template('dashboard.html', user=user, device_count=device_count, active_threats=active_threats,
                           network_anomalies=network_anomalies, blockchain_entries=blockchain_entries,
                           cloud_predictions=cloud_predictions, local_ip=local_ip, default_gateway=default_gateway,
                           dns_suffix=dns_suffix, is_admin=is_admin)

# === THREAT INTEL DASHBOARD ===
@app.route('/threat_intel')
def threat_intel():
    app.logger.info("Threat Intel page accessed")
    threats = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).limit(10).all()
    return render_template('threat_intel.html', threats=threats)

# === THREAT PAGE ===
@app.route('/threat')
def threat():
    threat_data = [
        {'timestamp': '2023-10-01', 'count': 5},
        {'timestamp': '2023-10-02', 'count': 8},
        {'timestamp': '2023-10-03', 'count': 3},
        {'timestamp': '2023-10-04', 'count': 12},
        {'timestamp': '2023-10-05', 'count': 7}
    ]
    return render_template('threat.html', threat_data=threat_data)

# === DEVICE MANAGER ===
@app.route('/device_manager')
def device_manager():
    app.logger.info("Device Manager page accessed")
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template('device_manager.html', devices=devices)

# === DEVICES PAGE ===
@app.route('/devices')
def devices():
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template('devices.html', devices=devices)

# === COMPLIANCE PAGE ===
@app.route('/compliance')
def compliance():
    last_audit = "November 2025"
    next_audit = "May 2026"
    officer = "John Doe"
    email = "compliance@mtac.ac.ug"
    return render_template('compliance.html', last_audit=last_audit, next_audit=next_audit, officer=officer, email=email)

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
        sample_threats = [
            ("192.168.1.100", "IP", "Firewall", "High", datetime.utcnow()),
            ("malware.exe", "File", "Antivirus", "Critical", datetime.utcnow()),
            ("Anomaly", "Behavior", "AI", "Medium", datetime.utcnow())
        ]
        for ioc, typ, source, risk, ts in sample_threats:
            t = ThreatLog(ioc=ioc, type=typ, source=source, risk=risk, timestamp=ts)
            db.session.add(t)
        db.session.commit()
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
    print(" * Login: /login")
    print(" * Register: /register")
    print(" * Dashboard: /dashboard_page")
    print(" * Threat Intel: /threat_intel")
    print(" * Threat: /threat")
    print(" * Device Manager: /device_manager")
    print(" * Devices: /devices")
    print(" * Compliance: /compliance")
    print(" * Health: /dashboard")
    print(" * LOG FILE: logs/app.log\n")
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])
>>>>>>> 0be6a386bdf743bca23f23412f15d069d0666896
