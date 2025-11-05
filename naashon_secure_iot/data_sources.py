gimport random
import time
from datetime import datetime, timedelta

# Mock data sources for dashboard metrics
# In production, these would connect to real databases, APIs, or sensors

class DataSources:
    def __init__(self):
        self.devices = []
        self.threats = []
        self.anomalies = []
        self.blockchain_entries = []
        self.predictions = []

    def get_total_devices(self):
        """Get total number of connected IoT devices"""
        # Simulate device count with some variation
        base_count = 1200
        variation = random.randint(-50, 50)
        return max(0, base_count + variation)

    def get_active_threats(self):
        """Get number of active security threats"""
        # Simulate threat detection
        threat_levels = [0, 1, 2, 3, 5, 8, 12, 15]
        return random.choice(threat_levels)

    def get_network_anomalies(self):
        """Get number of network anomalies detected"""
        # Simulate anomaly detection
        anomaly_counts = [0, 1, 2, 3, 4, 5, 7, 10]
        return random.choice(anomaly_counts)

    def get_blockchain_entries(self):
        """Get number of blockchain entries logged"""
        # Simulate blockchain logging
        base_entries = 85
        new_entries = random.randint(0, 5)
        self.blockchain_entries.append({
            'timestamp': datetime.now(),
            'type': 'log_entry',
            'data': f'Entry {len(self.blockchain_entries) + 1}'
        })
        return base_entries + len(self.blockchain_entries)

    def get_cloud_predictions(self):
        """Get number of AI predictions made"""
        # Simulate cloud AI predictions
        base_predictions = 40
        new_predictions = random.randint(0, 3)
        self.predictions.append({
            'timestamp': datetime.now(),
            'prediction': f'Prediction {len(self.predictions) + 1}',
            'confidence': random.uniform(0.7, 0.95)
        })
        return base_predictions + len(self.predictions)

    def get_recent_threats(self):
        """Get recent threat data for charts"""
        # Generate mock threat data for the last 24 hours
        now = datetime.now()
        threat_data = []
        for i in range(24):
            timestamp = now - timedelta(hours=23-i)
            threat_count = random.randint(0, 20)
            threat_data.append({
                'timestamp': timestamp.strftime('%H:%M'),
                'count': threat_count
            })
        return threat_data

    def get_device_status(self, device_id):
        """Get status of a specific device"""
        # Mock device status
        statuses = ['online', 'offline', 'maintenance']
        return random.choice(statuses)

    def control_device(self, device_id, action):
        """Control a device (restart, update, ping, etc.)"""
        # Mock device control response
        responses = {
            'restart': 'Device restarted successfully',
            'update': 'Firmware update initiated',
            'ping': 'Device pinged successfully',
            'remove': 'Device removed from network',
            'monitor': 'Monitoring enabled'
        }
        return responses.get(action, 'Unknown action')

# Global instance
data_sources = DataSources()
