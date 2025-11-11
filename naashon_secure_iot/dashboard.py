"""
NaashonSecureIoT – Main Flask Application
- APA Guide landing page
- Threat Intel, Device Manager, Health Check
- Real-time MTAC Dashboard (advanced UI)
"""

import os
import socket
import threading
import time
import subprocess
from flask import Flask, render_template, jsonify, request, render_template_string
from .config import Config, setup_logging
from .models import db, User, ThreatLog, Device
from datetime import datetime

# --------------------------------------------------------------------------- #
# 1. Flask App Setup
# --------------------------------------------------------------------------- #
app = Flask(__name__, template_folder='../templates')
app.config.from_object(Config)

db.init_app(app)
setup_logging(app)

# --------------------------------------------------------------------------- #
# 2. Database Initialisation & Seed Data
# --------------------------------------------------------------------------- #
with app.app_context():
    db.create_all()
    app.logger.info("Database initialized.")

    # Seed ThreatLog (placeholder – replace with real data later)
    if ThreatLog.query.count() == 0:
        app.logger.info("Seeding sample threat data")
        sample_threats = [
            ("192.168.1.105", "port_scan", "Malware-C2", "high"),
            ("10.0.0.42", "brute_force", "SSH-Scanner", "medium"),
        ]
        for ioc, typ, src, risk in sample_threats:
            t = ThreatLog(ioc=ioc, type=typ, source=src, risk=risk)
            db.session.add(t)
        db.session.commit()

    # Seed Devices
    if Device.query.count() == 0:
        app.logger.info("Seeding device data")
        sample_devices = [
            ("Router-01", "192.168.1.1", "00:1A:2B:3C:4D:5E", "online"),
            ("Camera-02", "192.168.1.102", "AA:BB:CC:DD:EE:FF", "offline"),
            ("Sensor-03", "192.168.1.103", "11:22:33:44:55:66", "online")
        ]
        for name, ip, mac, status in sample_devices:
            d = Device(name=name, ip=ip, mac=mac, status=status)
            db.session.add(d)
        db.session.commit()

# --------------------------------------------------------------------------- #
# 3. Core Routes (APA Guide, Threat Intel, Device Manager, Health)
# --------------------------------------------------------------------------- #
@app.route('/')
def index():
    app.logger.info("Landing page (APA Guide) loaded")
    return render_template('apa_guide_static.html')

@app.route('/threat_intel')
def threat_intel():
    app.logger.info("Threat Intel page accessed")
    threats = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).limit(10).all()
    return render_template('threat_intel.html', threats=threats)

@app.route('/device_manager')
def device_manager():
    app.logger.info("Device Manager page accessed")
    devices = Device.query.order_by(Device.last_seen.desc()).all()
    return render_template('device_manager.html', devices=devices, now=datetime.utcnow())

@app.route('/dashboard')
def dashboard():
    app.logger.info(f"Health check from {request.remote_addr}")
    return jsonify({
        "status": "OK",
        "users": User.query.count(),
        "threats": ThreatLog.query.count(),
        "devices": Device.query.count()
    })

# --------------------------------------------------------------------------- #
# 4. Real-time MTAC Dashboard (advanced UI)
# --------------------------------------------------------------------------- #
HTML_MTAC_DASHBOARD = """
<!DOCTYPE html>
<html>
<head>
  <title>NaashonSecureIoT - MTAC Dashboard</title>
  <meta http-equiv="refresh" content="5">
  <style>
    body {font-family: 'Courier New', monospace; background:#0d1117; color:#c9d1d9; padding:20px;}
    .container {max-width:1000px; margin:auto;}
    h1 {color:#58a6ff;}
    .metric {background:#161b22; padding:15px; margin:10px 0; border-radius:8px; border-left:4px solid #58a6ff;}
    .status-ok {color:#56d364;}
    .status-warn {color:#f85149;}
    .log {background:#21262d; padding:10px; height:200px; overflow-y:auto; font-size:0.9em;}
    pre {margin:0;}
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
      fetch('/api/mtac_metrics')
        .then(r => r.json())
        .then(data => {
          const m = document.getElementById('metrics');
          m.innerHTML = `
            <div class="metric"><strong>Status:</strong> <span class="${data.status==='secure'?'status-ok':'status-warn'}">${data.status.toUpperCase()}</span></div>
            <div class="metric"><strong>Devices Registered:</strong> ${data.devices}</div>
            <div class="metric"><strong>Anomaly Rate:</strong> ${data.anomaly_rate}%</div>
            <div class="metric"><strong>Blockchain Size:</strong> ${data.blockchain_blocks} blocks</div>
            <div class="metric"><strong>Uptime:</strong> ${data.uptime}s</div>
          `;
        });
    }
    function fetchLogs() {
      fetch('/api/mtac_logs')
        .then(r => r.text())
        .then(text => {
          const lines = text.trim().split('\\n').slice(-20);
          document.getElementById('logs').innerHTML = '<pre>' + lines.join('\\n') + '</pre>';
        });
    }
    setInterval(() => { fetchMetrics(); fetchLogs(); }, 3000);
    fetchMetrics(); fetchLogs();
  </script>
</body>
</html>
"""

@app.route('/mtac_dashboard')
def mtac_dashboard():
    return render_template_string(HTML_MTAC_DASHBOARD)

@app.route('/api/mtac_metrics')
def api_mtac_metrics():
    # Simulated metrics – replace with real framework calls later
    anomaly_rate = 0.05  # 5%
    return jsonify({
        "status": "secure" if anomaly_rate < 0.1 else "warning",
        "devices": Device.query.count(),
        "anomaly_rate": round(anomaly_rate * 100, 2),
        "blockchain_blocks": 1247,
        "uptime": int(time.time() - app.start_time) if hasattr(app, 'start_time') else 0
    })

@app.route('/api/mtac_logs')
def api_mtac_logs():
    # Simulated log lines
    logs = [
        "INFO: Device MTAC-DEV-001 registered",
        "INFO: Normal data logged",
        "WARNING: Anomaly detected on MTAC-DEV-999",
        "INFO: Quarantine triggered",
        "INFO: Cloud alert sent"
    ]
    return "\\n".join(logs[-20:])

# --------------------------------------------------------------------------- #
# 5. Error Handlers
# --------------------------------------------------------------------------- #
@app.errorhandler(404)
def not_found(e):
    app.logger.error(f"404: {request.url}")
    return "Page not found", 404

@app.errorhandler(500)
def server_error(e):
    app.logger.error(f"500: {str(e)}")
    return "Server error", 500

# --------------------------------------------------------------------------- #
# 6. Port & Firewall Helper (run once)
# --------------------------------------------------------------------------- #
def open_port():
    cmds = [
        "sudo ufw allow 5000/tcp",
        "sudo ufw reload",
        "sudo iptables -I INPUT -p tcp --dport 5000 -j ACCEPT"
    ]
    for cmd in cmds:
        print(f"[RUN] {cmd}")
        subprocess.run(cmd, shell=True, capture_output=True)

def check_access():
    s = socket.socket()
    try:
        s.connect(("127.0.0.1", 5000))
        return True
    except Exception:
        return False
    finally:
        s.close()

# --------------------------------------------------------------------------- #
# 7. Application Entry Point
# --------------------------------------------------------------------------- #
if __name__ == '__main__':
    # Record start time for uptime
    app.start_time = time.time()

    print("\n=== NaashonSecureIoT ===")
    print(" * Landing Page: / (APA Guide)")
    print(" * Threat Intel: /threat_intel")
    print(" * Device Manager: /device_manager")
    print(" * MTAC Dashboard: /mtac_dashboard")
    print(" * Health Check: /dashboard")
    print(" * LOG FILE: logs/app.log\n")

    # Optional: open firewall (uncomment on first run)
    # open_port()

    if not check_access():
        print("[INFO] Starting Flask in debug mode...")
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'], use_reloader=False)
