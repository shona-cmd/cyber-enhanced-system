from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
# from naashon_secure_iot import core  # Commented out for now
import json
from authlib.integrations.flask_client import OAuth
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from data_sources import data_sources

template_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '../templates')
static_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '../static')
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.secret_key = os.environ.get('SECRET_KEY', 'naashon_secure_iot_secret_key')  # Use environment variable in production

# OAuth configuration
oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id='your_github_client_id',  # Replace with actual GitHub OAuth app client ID
    client_secret='your_github_client_secret', # Replace with actual GitHub OAuth app client secret
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

facebook = oauth.register(
    name='facebook',
    client_id='your_facebook_app_id',  # Replace with actual Facebook app ID
    client_secret='your_facebook_app_secret', # Replace with actual GitHub OAuth app client secret
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email'},
)

# Simple user storage (in production, use database)
USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.json')

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {'admin@example.com': {'password': 'admin123', 'role': 'admin'}}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with open('users.txt', 'r') as f:
            for line in f:
                u, p = line.strip(':')
                if username == u and password == p:
                    return redirect("/")
        return "Invalid credentials"
    return render_template("login.html")


@app.route("/")
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get real-time dashboard data from data sources
    dashboard_data = {
        "total_devices": data_sources.get_total_devices(),
        "active_threats": data_sources.get_recent_threats(),
        "network_anomalies": data_sources.get_network_anomalies(),
        "blockchain_entries": data_sources.get_blockchain_entries()
    }

    # Check if user is admin to show additional features
    is_admin = session['user'].get('role') == 'admin'

    from naashon_secure_iot.config import Config
    config = Config()
    return render_template("dashboard.html",
                           device_count=dashboard_data["total_devices"],
                           active_threats=dashboard_data["active_threats"],
                           network_anomalies=dashboard_data["network_anomalies"],
                           blockchain_entries=dashboard_data["blockchain_entries"],
                           cloud_predictions=data_sources.get_cloud_predictions(),
                           user=session['user'],
                           is_admin=is_admin,
                           local_ip=config.local_ip,
                           subnet_mask=config.subnet_mask,
                           default_gateway=config.default_gateway,
                           dns_suffix=config.dns_suffix,
                           mqtt_broker=config.mqtt_broker)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        users = load_users()
        if email in users and users[email]['password'] == password:
            session['user'] = {'email': email, 'role': users[email]['role']}
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')

    return render_template("login.html")

import uuid

import json

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data['username']
            password = data['password']
            device_id = str(uuid.uuid4())  # Generate a unique device ID

            # Store the data (replace with actual storage logic)
            with open('users.txt', 'a') as f:
                f.write(f'{username}:{password}:{device_id}\n')
            return json.dumps({
                'message': 'Registration successful!',
                'device_id': device_id
            }), 200, {'ContentType': 'application/json'}
        except Exception as e:
            return json.dumps({
                'error': str(e)
            }), 400, {'ContentType': 'application/json'}
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route("/threat")
def threat():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get threat data for the page
    threat_data = data_sources.get_recent_threats()

    return render_template("dashboard.html",
                          user=session['user'],
                          is_admin=session['user'].get('role') == 'admin',
                          threat_data=threat_data)

@app.route("/devices")
def devices():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Mock device data with dynamic status
    devices_data = [
        {'id': 'device1', 'name': 'IoT Device 1', 'status': data_sources.get_device_status('device1')},
        {'id': 'device2', 'name': 'IoT Device 2', 'status': data_sources.get_device_status('device1')},
        {'id': 'device3', 'name': 'IoT Device 3', 'status': data_sources.get_device_status('device1')}
    ]

    return render_template("dashboard.html",
                          user=session['user'],
                          is_admin=session['user'].get('role') == 'admin',
                          devices_data=devices_data)

@app.route("/control_device/<device_id>/<action>")
def control_device(device_id, action):
    if 'user' not in session:
        return redirect(url_for('login'))

    # Perform device control action
    result = data_sources.control_device(device_id, action)

    # Redirect back to devices page with a flash message
    flash(f"Device {device_id}: {result}")
    return redirect(url_for('devices'))

@app.route('/login/github')
def login_github():
    github = oauth.create_client('github')
    redirect_uri = url_for('authorize_github', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/login/facebook')
def login_facebook():
    facebook = oauth.create_client('facebook')
    redirect_uri = url_for('authorize_facebook', _external=True)
    return facebook.authorize_redirect(redirect_uri)

@app.route('/authorize/github')
def authorize_github():
    github = oauth.create_client('github')
    token = github.authorize_access_token()
    resp = github.get('user')
    profile = resp.json()
    # Get user email
    email_resp = github.get('user/emails')
    emails = email_resp.json()
    primary_email = next((email['email'] for email in emails if email['primary']), profile['email'])

    # Create or update user in session
    session['user'] = {
        'email': primary_email,
        'name': profile.get('name', ''),
        'role': 'user',
        'provider': 'github'
    }
    return redirect(url_for('dashboard'))

@app.route('/authorize/facebook')
def authorize_facebook():
    facebook = oauth.create_client('facebook')
    token = facebook.authorize_access_token()
    resp = facebook.get('me?fields=id,name,email')
    profile = resp.json()
    try:
        email = profile.get('email', '')
    except:
        email = ""
    # Create or update user in session
    session['user'] = {
        'email': email,
        'name': profile.get('name', ''),
        'role': 'user',
        'provider': 'facebook'
    }
    return redirect(url_for('dashboard'))

@app.route('/register/github')
def register_github():
    github = oauth.create_client('github')
    redirect_uri = url_for('authorize_register_github', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/authorize/register/facebook')
def authorize_register_facebook():
    try:
        facebook = oauth.create_client('facebook')
        token = facebook.authorize_access_token()
        resp = resp.get('me?fields=id,name,email')
        profile = resp.json()
        try:
            email = profile.get('email', '')
        except:
            email = ""
        if not email:
            flash('Email not provided by Facebook')
            return redirect(url_for('register'))

        users = load_users()
        if email in users:
            flash('User already exists')
            return redirect(url_for('register'))

        # Create new user
        users[email] = {
            'password': '', # No password for OAuth users
            'role': 'user'
        }
        save_users(users)

        # Log in the user
        session['user'] = {
            'email': email,
            'name': profile.get('name', ''),
            'role': 'user',
            'provider': 'facebook'
        }
        flash('Registration successful!')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('Facebook registration failed. Please try again.')
        return redirect(url_for('register'))


@app.route("/api/register_device", methods=['POST'])
def api_register_device():
    from naashon_secure_iot import core
    framework = core.NaashonSecureIoT()
    data = request.get_json()
    device_id = data and data.get('device_id')
    device_type = data.get('device_type', 'unknown')
    if framework.register_device(device_id, device_type):
        message = f"Device with id {device_id} registered"
        return {"status": "success", "message": message}
    else:
        message = f"Failed to register device with id {device_id}"
        return {"status": "error", "message": message}, 400


@app.route("/api/transmit_data", methods=['POST'])
def api_transmit_data():
    from naashon_secure_iot import core
    framework = core.NaashonSecureIoT()
    data = request.get_json()
    device_id = data and data.get('device_id')
    payload = data.get('data')
    if isinstance(payload, str):
        payload = {"message": f"Data received from device with id {device_id}", "timestamp": None}
    result = framework.process_data(device_id, payload)
    return result


@app.route("/api/metrics")
def api_metrics():
    from naashon_secure_iot import core
    framework = core.NaashonSecureIoT()
    data = framework.get_dashboard_data()
    status = "secure" if data["active_threats"] < 5 else "warning"
    return {
        "status": status,
        "devices": data["total_devices"],
        "anomaly_rate": 0.0,  # Placeholder
        "blockchain_blocks": data["blockchain_blocks"],
        "uptime": 0  # Placeholder
    }


@app.route("/apa_guide")
def apa_guide():
    return render_template("apa_guide.html")


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
