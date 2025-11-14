from flask import Flask, render_template, send_from_directory, request, session, flash, redirect, url_for
from functools import wraps
import os

app = Flask(__name__, static_url_path='/static')
app.secret_key = 'naashonhq_mtac_secure_2025'

@app.route('/')
def home():
    return render_template('apa_cover.html')

@app.route('/quote')
def quote():
    return render_template('quote.html')

@app.route('/download_report')
def download_report():
    return send_from_directory(
        'static/reports',
        'compliance_report_nov2025.pdf',
        as_attachment=True
    )

# === USER DATABASE (In real app: use SQLite) ===
users = {
    'admin': {'password': 'admin123', 'role': 'admin'},
    'hod': {'password': 'hod123', 'role': 'hod'},
    'user': {'password': 'user123', 'role': 'user'}
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

@app.route('/login')
def login():
    return send_from_directory('.', 'templates/login.html')

@app.route('/register')
def register():
    return send_from_directory('.', 'templates/register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/threat_intel')
@login_required
def threat_intel():
    return render_template('threat_intel.html')

@app.route('/device_manager')
@login_required
@hod_required
def device_manager():
    return render_template('device_manager.html')

@app.route('/admin_panel')
@login_required
@admin_required
def admin_panel():
    return render_template('admin_panel.html')

@app.route('/download_report')
def download_report():
    return send_from_directory(os.path.join(app.root_path, 'static/reports'), 'compliance_report_nov2025.pdf', as_attachment=True)

@app.route('/hello/<name>')
def hello(name):
    return f"Hello, {name}!"

if __name__ == '__main__':
    app.run(debug=True, port=5000)
