from flask import Flask, render_template, request, redirect
import os
from naashon_secure_iot import core

template_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '../templates')
static_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '../static')
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with open('users.txt', 'r') as f:
            for line in f:
                u, p = line.strip().split(':')
                if username == u and password == p:
                    return redirect("/")
        return "Invalid credentials"
    return render_template("dashboard.html")


@app.route("/")
def dashboard():
    # Initialize the NaashonSecureIoT framework
    framework = core.NaashonSecureIoT()

    # Get system status and metrics
    dashboard_data = framework.get_dashboard_data()

    return render_template(
        "dashboard.html",
        device_count=dashboard_data["total_devices"],
        active_threats=dashboard_data["active_threats"],
        network_anomalies=dashboard_data["network_anomalies"],
        blockchain_entries=dashboard_data["blockchain_entries"],
        cloud_predictions=dashboard_data["cloud_predictions"]
    )


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


@app.route("/api/register_device", methods=['POST'])
def api_register_device():
    from naashon_secure_iot import core
    framework = core.NaashonSecureIoT()
    data = request.get_json()
    device_id = data.get('device_id')
    device_type = data.get('device_type', 'unknown')
    if framework.register_device(device_id, device_type):
        message = f"Device {device_id} registered"
        return {"status": "success", "message": message}
    else:
        message = f"Failed to register device {device_id}"
        return {"status": "error", "message": message}, 400


@app.route("/api/transmit_data", methods=['POST'])
def api_transmit_data():
    from naashon_secure_iot import core
    framework = core.NaashonSecureIoT()
    data = request.get_json()
    device_id = data.get('device_id')
    payload = data.get('data')
    if isinstance(payload, str):
        payload = {"message": payload, "timestamp": None}
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
        "blockchain_blocks": data["blockchain_entries"],
        "uptime": 0  # Placeholder
    }


@app.route("/api/logs")
def api_logs():
    # Simulated logs
    log_message = "INFO: System initialized\n"
    log_message += "INFO: Device registered\n"
    log_message += "WARNING: Anomaly detected"
    return log_message


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
