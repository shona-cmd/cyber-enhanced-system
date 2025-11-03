from flask import Flask, render_template
import os

template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '../templates')
app = Flask(__name__, template_folder=template_dir)


@app.route("/")
def dashboard():
    # Initialize the NaashonSecureIoT framework
    # framework = core.NaashonSecureIoT()

    # Get system status and metrics (replace with actual data retrieval)
    device_count = 10
    edge_alerts = 5
    network_anomalies = 2
    blockchain_transactions = 100

    return render_template("dashboard.html",
                           device_count=device_count,
                           edge_alerts=edge_alerts,
                           network_anomalies=network_anomalies,
                           blockchain_transactions=blockchain_transactions)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
