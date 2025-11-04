nafrom flask import Flask, render_template
import os
from naashon_secure_iot import core

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../templates')
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../static')
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)


@app.route("/")
def dashboard():
    # Initialize the NaashonSecureIoT framework
    framework = core.NaashonSecureIoT()

    # Get system status and metrics
    dashboard_data = framework.get_dashboard_data()

    return render_template("dashboard.html",
                           device_count=dashboard_data["total_devices"],
                           active_threats=dashboard_data["active_threats"],
                           network_anomalies=dashboard_data["network_anomalies"],
                           blockchain_entries=dashboard_data["blockchain_entries"],
                           cloud_predictions=dashboard_data["cloud_predictions"])


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
