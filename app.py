from flask import Flask, render_template, url_for, session, redirect, flash, request
from functools import wraps
import os

app = Flask(__name__, static_url_path='/static')
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-prod')

@app.route('/quote')
def quote():
    return render_template('quote.html')

# === USER DATABASE (In real app: use SQLite) ===
# NOTE: In production, use proper database with hashed passwords
# These are demo credentials - change in production!
users = {
    'admin': {'password': os.getenv('ADMIN_PASSWORD', 'change_me_in_prod'), 'role': 'admin'},
    'hod': {'password': os.getenv('HOD_PASSWORD', 'change_me_in_prod'), 'role': 'hod'},
    'user': {'password': os.getenv('USER_PASSWORD', 'change_me_in_prod'), 'role': 'user'}
}

# === LOGIN REQUIRED DECORATOR ===
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# === ROLE CHECK DECORATORS ===
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            flash("Admin access only!", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def hod_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') not in ['admin', 'hod']:
            flash("HOD or Admin access only!", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# === ROUTES ===
@app.route('/')
def home():
    return render_template('apa_cover.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check credentials
        if email in users and users[email]['password'] == password:
            session['user'] = email
            session['role'] = users[email]['role']
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials!", "danger")
            return render_template('login.html', error="Invalid email or password")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Basic validation
        if not all([name, email, password, confirm_password]):
            flash("All fields are required!", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        if len(password) < 6:
            flash("Password must be at least 6 characters long!", "danger")
            return redirect(url_for('register'))

        # Check if user already exists (in real app, check database)
        # For demo purposes, we'll just flash success
        flash("Registration successful! You can now login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = {'name': 'Test User', 'email': 'test@example.com'}
    device_count = 100
    active_threats = 10
    network_anomalies = 5
    blockchain_entries = 1000
    cloud_predictions = 50
    local_ip = "192.168.1.1"
    default_gateway = "192.168.1.254"
    dns_suffix = "example.com"
    is_admin = True
    return render_template(
        "dashboard.html",
        user=user,
        device_count=device_count,
        active_threats=active_threats,
        network_anomalies=network_anomalies,
        blockchain_entries=blockchain_entries,
        cloud_predictions=cloud_predictions,
        local_ip=local_ip,
        default_gateway=default_gateway,
        dns_suffix=dns_suffix,
        is_admin=is_admin,
    )

@app.route('/admin_panel')
@login_required
@admin_required
def admin_panel():
    return render_template('admin_panel.html')

@app.route('/view_logs')
@login_required
@admin_required
def view_logs():
    return "Logs page - functionality to be implemented"

@app.route('/manage_users')
@login_required
@admin_required
def manage_users():
    return "Manage Users page - functionality to be implemented"

@app.route('/view_alerts')
@login_required
@admin_required
def view_alerts():
    return "View Alerts page - functionality to be implemented"

@app.route('/run_scan')
@login_required
@admin_required
def run_scan():
    return "Scan initiated - functionality to be implemented"

@app.route('/generate_report')
@login_required
@admin_required
def generate_report():
    return "Report generated - functionality to be implemented"

@app.route('/audit_logs')
@login_required
@admin_required
def audit_logs():
    return "Audit Logs page - functionality to be implemented"

if __name__ == "__main__":
    app.run(debug=True, port=5500)
