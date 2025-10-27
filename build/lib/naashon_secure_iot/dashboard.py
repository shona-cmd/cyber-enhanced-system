"""
Web Dashboard for NaashonSecureIoT.

Provides real-time monitoring and visualization of system status and metrics.
"""

import threading
import time
from flask import Flask, render_template_string, jsonify
from typing import Dict, Any
from .core import NaashonSecureIoT


class IoTDashboard:
    """Web dashboard for monitoring NaashonSecureIoT framework."""

    def __init__(self, framework: NaashonSecureIoT, host: str = "localhost", port: int = 5000):
        self.framework = framework
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.thread = None
        self.running = False

        # Setup routes
        self._setup_routes()

    def _setup_routes(self):
        """Setup Flask routes for the dashboard."""

        @self.app.route('/')
        def index():
            return render_template_string(self._get_html_template())

        @self.app.route('/api/status')
        def api_status():
            return jsonify(self.framework.get_system_status())

        @self.app.route('/api/metrics')
        def api_metrics():
            return jsonify(self._get_metrics())

        @self.app.route('/api/blockchain')
        def api_blockchain():
            entries = self.framework.blockchain_layer.get_recent_entries(10)
            return jsonify(entries)

        @self.app.route('/api/threats')
        def api_threats():
            intel = self.framework.cloud_layer.get_threat_intelligence()
            return jsonify(intel)

    def _get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive system metrics."""
        return {
            "edge_metrics": self.framework.edge_layer.get_model_metrics(),
            "network_status": self.framework.network_layer.get_network_status(),
            "blockchain_count": self.framework.blockchain_layer.get_entry_count(),
            "cloud_predictions": self.framework.cloud_layer.get_prediction_count(),
            "cloud_backups": self.framework.cloud_layer.get_backup_count(),
            "active_devices": len(self.framework.device_layer.get_all_devices())
        }

    def _get_html_template(self) -> str:
        """Get HTML template for the dashboard."""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>NaashonSecureIoT Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .metric-card { background: white; padding: 20px; margin: 10px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); display: inline-block; width: 300px; vertical-align: top; }
        .status-good { color: #27ae60; }
        .status-warning { color: #f39c12; }
        .status-error { color: #e74c3c; }
        .refresh-btn { background: #3498db; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        .refresh-btn:hover { background: #2980b9; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
    <script>
        function refreshData() {
            fetch('/api/status').then(r => r.json()).then(data => {
                document.getElementById('total-devices').textContent = data.total_devices;
                document.getElementById('active-threats').textContent = data.active_threats;
                document.getElementById('blockchain-entries').textContent = data.blockchain_entries;
            });

            fetch('/api/metrics').then(r => r.json()).then(data => {
                document.getElementById('cloud-predictions').textContent = data.cloud_predictions;
                document.getElementById('cloud-backups').textContent = data.cloud_backups;
                document.getElementById('active-devices').textContent = data.active_devices;
            });
        }

        setInterval(refreshData, 5000); // Refresh every 5 seconds
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>NaashonSecureIoT Dashboard</h1>
            <p>Real-time monitoring for MTAC IoT Cybersecurity Enhancement</p>
            <button class="refresh-btn" onclick="refreshData()">Refresh Data</button>
        </div>

        <div class="metric-card">
            <h3>System Status</h3>
            <p>Total Devices: <span id="total-devices">0</span></p>
            <p>Active Threats: <span id="active-threats">0</span></p>
            <p>Blockchain Entries: <span id="blockchain-entries">0</span></p>
            <p>System Health: <span class="status-good">Operational</span></p>
        </div>

        <div class="metric-card">
            <h3>Cloud Analytics</h3>
            <p>Predictions Made: <span id="cloud-predictions">0</span></p>
            <p>Data Backups: <span id="cloud-backups">0</span></p>
            <p>Active Devices: <span id="active-devices">0</span></p>
        </div>

        <div class="metric-card">
            <h3>Edge Layer</h3>
            <p>Anomaly Threshold: 0.85</p>
            <p>Model Status: <span class="status-good">Loaded</span></p>
            <p>Federated Learning: <span class="status-good">Enabled</span></p>
        </div>

        <div style="clear: both;"></div>

        <h2>Recent Blockchain Entries</h2>
        <div id="blockchain-entries-table">
            <table>
                <thead>
                    <tr>
                        <th>Hash</th>
                        <th>Type</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>
                <tbody id="blockchain-tbody">
                    <tr><td colspan="3">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <script>
            function loadBlockchainEntries() {
                fetch('/api/blockchain').then(r => r.json()).then(entries => {
                    const tbody = document.getElementById('blockchain-tbody');
                    tbody.innerHTML = '';
                    entries.forEach(entry => {
                        const row = `<tr>
                            <td>${entry.hash.substring(0, 16)}...</td>
                            <td>${entry.data.type || 'unknown'}</td>
                            <td>${new Date(entry.timestamp * 1000).toLocaleString()}</td>
                        </tr>`;
                        tbody.innerHTML += row;
                    });
                });
            }

            loadBlockchainEntries();
            setInterval(loadBlockchainEntries, 10000); // Refresh blockchain data every 10 seconds
        </script>
    </div>
</body>
</html>
        """

    def start(self):
        """Start the dashboard server in a separate thread."""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_server)
        self.thread.daemon = True
        self.thread.start()
        print(f"Dashboard started at http://{self.host}:{self.port}")

    def _run_server(self):
        """Run the Flask server."""
        self.app.run(host=self.host, port=self.port, debug=False, use_reloader=False)

    def stop(self):
        """Stop the dashboard server."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1)
        print("Dashboard stopped")

    def is_running(self) -> bool:
        """Check if dashboard is running."""
        return self.running
