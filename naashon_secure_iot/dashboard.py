"""
NaashonSecureIoT - Dashboard Visibility Fix
Ensures Flask web UI is accessible, ports open, and metrics rendered.

Author: Grok (programmer mode)
Target: MTAC Edge/Cloud Node
"""

import os
import socket
import threading
import time
import subprocess
from flask import Flask, render_template, jsonify, request
from flask import redirect, url_for, flash
from naashon_secure_iot.core import NaashonSecureIoT
from naashon_secure_iot.data_sources import data_sources

# === 1. PORT & HOST CONFIG ===
HOST = "0.0.0.0"  # Bind to all
# interfaces
PORT = 5000
DASHBOARD_URL = (
    f"http://localhost:{PORT}"
)

# === 2. ENHANCED DASHBOARD TEMPLATE ===
HTML_DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
  <title>NaashonSecureIoT - MTAC Dashboard</title>
  <meta http-equiv="refresh" content="5">
  <style>
    body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
    .container { max-width: 1000px; margin: auto; }
    h1 { color: #58a6ff; }
    .metric { background: #161b22; padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid #58a6ff; }
    .status-ok { color: #56d364; }
    .status-warn { color: #f85149; }
    .log { background: #21262d; padding: 10px; height: 200px; overflow-y: auto; font-size: 0.9em; }
    pre { margin: 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>NaashonSecureIoT @ MTAC</h1>
    <div id="metrics"></div>
    <h2>Live Logs</h2>
    <div id="logs" class="log"></div>
  </div>

  <script>
    function fetchMetrics() {
      fetch('/api/metrics')
        .then(r => r.json())
        .then(data => {
          const m = document.getElementById('metrics');
          m.innerHTML = `
            <div class="metric"><strong>Status:</strong> <span class="${data.status === 'secure' ? 'status-ok' : 'status-warn'}">${data.status.toUpperCase()}</span></div>
            <div class="metric"><strong>Devices Registered:</strong> ${data.devices}</div>
            <div class="metric"><strong>Anomaly Rate:</strong> ${data.anomaly_rate}%</div>
            <div class="metric"><strong>Blockchain Size:</strong> ${data.blockchain_blocks} blocks</div>
            <div class="metric"><strong>Uptime:</strong> ${data.uptime}s</div>
          `;
        });
    }

    function fetchLogs() {
      fetch('/api/logs')
        .then(r => r.text())
        .then(text => {
          document.getElementById('logs').innerHTML = '<pre>' + text.trim().split('\\n').slice(-20).join('\\n') + '</pre>';
        });
    }

    setInterval(() => { fetchMetrics(); fetchLogs(); }, 3000);
    fetchMetrics(); fetchLogs();
  </script>
</body>
</html>
"""

# === 3. FIX CORE DASHBOARD ROUTES ===
def patch_dashboard():
    framework = NaashonSecureIoT()
    app = Flask(__name__)
    app.secret_key = 'naashon_secure_iot_secret_key'

    # Re-add core API
    @app.route('/register_device', methods=['POST'])
    def register_device():
        data = request.json
        device_id = data.get('device_id')
        if not device_id:
            return jsonify({"error": "device_id required"}), 400
        if not framework.network.verify_identity(device_id):
            return jsonify({"error": "Identity failed"}), 403
        tx = framework.blockchain.register_device(device_id)
        return jsonify({"tx_hash": tx, "status": "registered"}), 200

    @app.route('/transmit_data', methods=['POST'])
    def transmit_data():
        payload = request.json
        device_id = payload['device_id']
        raw_data = (
            payload['data'].encode()
            if isinstance(payload['data'], str)
            else payload['data']
        )

        encrypted = framework.device.encrypt_data(raw_data)
        if not framework.network.authorize_transmission(device_id):
            framework.blockchain.log_anomaly(device_id, "Unauthorized")
            return jsonify({"error": "Access denied"}), 403

        is_anomaly, score = framework.edge.detect_anomaly(encrypted)
        if is_anomaly:
            framework.blockchain.trigger_quarantine(device_id)
            framework.cloud.alert_threat(device_id, score)
            return jsonify({"status": "anomaly_detected", "score": score}), 200

        tx = framework.blockchain.log_data(device_id, encrypted)
        framework.cloud.store_secure(encrypted, tx)
        return jsonify({"status": "secure", "tx": tx}), 200

    # === NEW: DASHBOARD & API ===
    @app.route('/')
    def dashboard():
        dashboard_data = framework.get_dashboard_data()
        return render_template(
            'dashboard.html',
            device_count=dashboard_data['total_devices'],
            active_threats=dashboard_data['active_threats'],
            blockchain_entries=dashboard_data['blockchain_entries'],
            network_anomalies=dashboard_data['network_anomalies'],
            cloud_predictions=dashboard_data['cloud_predictions'],
            mtac_name=dashboard_data['mtac_name']
        )

    @app.route('/threat')
    def threat():
        threat_data = data_sources.get_recent_threats()
        return render_template(
            'threat.html', threat_data=threat_data
        )

    @app.route('/devices')
    def devices():
        device_list = framework.device_layer.get_all_devices()
        return render_template(
            'devices.html', devices=device_list
        )

    @app.route('/control_device/<device_id>/<action>')
    def control_device(device_id, action):
        if action not in ['restart', 'update', 'ping', 'remove', 'monitor']:
            flash('Invalid action', 'error')
            return redirect(url_for('devices'))
        result = data_sources.control_device(
            device_id, action
        )
        flash(f'Device {device_id}: {result}', 'success')
        return redirect(url_for('devices'))

    @app.route('/logout')
    def logout():
        flash('Logged out successfully', 'info')
        return redirect(url_for('dashboard'))

    @app.route('/api/metrics')
    def api_metrics():
        metrics = framework.cloud.get_metrics()
        return jsonify({
            "status": "secure" if metrics["anomaly_rate"] < 0.1 else "warning",
            "devices": len([b for b in framework.blockchain.chain if "REGISTER" in b.data]),
            "anomaly_rate": round(metrics["anomaly_rate"] * 100, 2),
            "blockchain_blocks": len(framework.blockchain.chain),
            "uptime": int(
                time.time() - framework.cloud.start_time
                if hasattr(framework.cloud, 'start_time')
                else 0
            )
        })

    @app.route('/api/logs')
    def api_logs():
        # Capture recent logs (simulated)
        return "INFO: Device MTAC-DEV-001 registered\\nINFO: Normal data logged\\nWARNING: Anomaly detected on MTAC-DEV-999"

    return app

# === 4. PORT & FIREWALL FIX ===
def open_port():
    cmds = [
        "ufw allow 5000/tcp",
        "ufw reload",
        "iptables -I INPUT -p tcp --dport 5000 -j ACCEPT",
        "netstat -tuln | grep 5000 || echo 'Port 5000 not listening'"
    ]
    for cmd in cmds:
        print(f"[RUN] {cmd}")
        subprocess.run(cmd, shell=True)

def check_access():
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", PORT))
        print(f"[OK] Local access: {DASHBOARD_URL}")
        return True
    except:
        print(f"[FAIL] Cannot connect to"
              f" {DASHBOARD_URL}")
        return False
    finally:
        s.close()

# === 5. LAUNCH FIXED DASHBOARD ===
def launch():
    open_port()
    if not check_access():
        print("[FIX] Starting in debug mode...")
        app = patch_dashboard()
        app.run(
            host=HOST, port=PORT, debug=True,
            use_reloader=False
        )
    else:
        print(f"[OK] Dashboard live at {DASHBOARD_URL}")
        print("   Open in browser: curl -s http://localhost:5000 | head")

# === RUN ===
if __name__ == "__main__":
    print("# NaashonSecureIoT Dashboard Fix Script")
    print("# Killing old Flask processes...")
    os.system("pkill -f 'naashon_secure_iot' || true")
    time.sleep(2)

    print("# Starting fixed dashboard...")
    launch_thread = threading.Thread(target=launch)
    launch_thread.daemon = True
    launch_thread.start()

    print(f"\n[LAUNCH] Dashboard: {DASHBOARD_URL}")
    print("[TEST] Run: curl http://localhost:5000")
    print("[SIM] Run: python examples/iot_simulation.py")
    print("\nWaiting for dashboard to load... Press Ctrl+C to stop.\n")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[STOP] Dashboard stopped.")
