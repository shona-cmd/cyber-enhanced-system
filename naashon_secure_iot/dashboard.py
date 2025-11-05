from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
# from naashon_secure_iot import core  # Commented out for now
import json
from authlib.integrations.flask_client import OAuth
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from data_sources import data_sources

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../static')
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
app.secret_key = 'naashon_secure_iot_secret_key'  # In production, use environment variable

# OAuth configuration
oauth = OAuth(app)
github = oauth.register(
    name='github',
    client_id='your_github_client_id',  # Replace with actual GitHub OAuth app client ID
    client_secret='your_github_client_secret',  # Replace with actual GitHub OAuth app client secret
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
    client_secret='your_facebook_app_secret',  # Replace with actual Facebook app secret
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


@app.route("/")
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Get real-time dashboard data from data sources
    dashboard_data = {
        "total_devices": data_sources.get_total_devices(),
        "active_threats": data_sources.get_active_threats(),
        "network_anomalies": data_sources.get_network_anomalies(),
        "blockchain_entries": data_sources.get_blockchain_entries(),
        "cloud_predictions": data_sources.get_cloud_predictions()
    }

    # Check if user is admin to show additional features
    is_admin = session['user'].get('role') == 'admin'

    return render_template("dashboard.html",
                           device_count=dashboard_data["total_devices"],
                           active_threats=dashboard_data["active_threats"],
                           network_anomalies=dashboard_data["network_anomalies"],
                           blockchain_entries=dashboard_data["blockchain_entries"],
                           cloud_predictions=dashboard_data["cloud_predictions"],
                           user=session['user'],
                           is_admin=is_admin)

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

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role', 'user')

        users = load_users()
        if email in users:
            flash('User already exists')
        else:
            users[email] = {'password': password, 'role': role}
            save_users(users)
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

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

    # Create or update user in session
    session['user'] = {
        'email': profile.get('email', ''),
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

@app.route('/register/facebook')
def register_facebook():
    facebook = oauth.create_client('facebook')
    redirect_uri = url_for('authorize_register_facebook', _external=True)
    return facebook.authorize_redirect(redirect_uri)

@app.route('/authorize/register/github')
def authorize_register_github():
    try:
        github = oauth.create_client('github')
        token = github.authorize_access_token()
        resp = github.get('user')
        profile = resp.json()
        # Get user email
        email_resp = github.get('user/emails')
        emails = email_resp.json()
        primary_email = next((email['email'] for email in emails if email['primary']), profile['email'])

        users = load_users()
        if primary_email in users:
            flash('User already exists')
            return redirect(url_for('register'))

        # Create new user
        users[primary_email] = {
            'password': '',  # No password for OAuth users
            'role': 'user'
        }
        save_users(users)

        # Log in the user
        session['user'] = {
            'email': primary_email,
            'name': profile.get('name', ''),
            'role': 'user',
            'provider': 'github'
        }
        flash('Registration successful!')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash('GitHub registration failed. Please try again.')
        return redirect(url_for('register'))

@app.route('/authorize/register/facebook')
def authorize_register_facebook():
    try:
        facebook = oauth.create_client('facebook')
        token = facebook.authorize_access_token()
        resp = facebook.get('me?fields=id,name,email')
        profile = resp.json()

        email = profile.get('email', '')
        if not email:
            flash('Email not provided by Facebook')
            return redirect(url_for('register'))

        users = load_users()
        if email in users:
            flash('User already exists')
            return redirect(url_for('register'))

        # Create new user
        users[email] = {
            'password': '',  # No password for OAuth users
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


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
