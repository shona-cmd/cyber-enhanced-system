from flask import Flask, render_template, url_for
import os

app = Flask(__name__, static_folder='static')

@app.route("/")
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
