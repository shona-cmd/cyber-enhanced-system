from flask import Flask, render_template, url_for, session, redirect, flash
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

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
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

if __name__ == "__main__":
    app.run(debug=True)
=======
from flask import Flask, render_template, url_for, session, redirect, flash
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

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
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

if __name__ == "__main__":
    app.run(debug=True)
=======
from flask import Flask, render_template, url_for, session, redirect, flash
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

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
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

if __name__ == "__main__":
    app.run(debug=True)
=======
app = Flask(__name__, static_folder='static')

@app.route("/")
>>>>>>> 9adf6bc6a76c410760b3f7bbbbfa975ff5950c1b
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

if __name__ == "__main__":
    app.run(debug=True)
