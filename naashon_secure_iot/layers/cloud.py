"""
Cloud Layer for NaashonSecureIoT.

Handles AI threat intelligence, predictive analytics, and data backups.
"""

import logging
import time
from typing import Dict, Any, List
from ..config import Config
from ..utils.threat_intelligence import ThreatIntelligence


class CloudLayer:
    """Cloud layer for advanced analytics and threat intelligence."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.threat_intelligence_module = ThreatIntelligence()
        self.threat_intelligence: Dict[str, Any] = {}
        self.predictions: List[Dict[str, Any]] = []
        self.backup_data: List[Dict[str, Any]] = []
        self.logger.info("Cloud layer initialized")

    def analyze_and_backup(self, device_id: str, data: Dict[str, Any], anomaly_score: float):
        """
        Perform cloud-based analysis and backup data.

        Args:
            device_id: Device identifier
            data: IoT data payload
            anomaly_score: Anomaly score from edge layer
        """
        try:
            # Store backup
            backup_entry = {
                "device_id": device_id,
                "timestamp": time.time(),
                "data": data,
                "anomaly_score": anomaly_score
            }
            self.backup_data.append(backup_entry)

            # Perform predictive analytics
            prediction = self._predict_threats(data, anomaly_score)
            if prediction:
                self.predictions.append(prediction)

            # Update threat intelligence
            self._update_threat_intelligence(device_id, anomaly_score)

            self.logger.debug(f"Cloud analysis completed for device {device_id}")
        except Exception as e:
            self.logger.error(f"Cloud analysis failed for device {device_id}: {e}")

    def _predict_threats(self, data: Dict[str, Any], anomaly_score: float) -> Dict[str, Any]:
        """
        Perform predictive threat analysis.

        Args:
            data: IoT data
            anomaly_score: Current anomaly score

        Returns:
            Prediction results
        """
        # Simple prediction logic - could be enhanced with ML models
        prediction = {
            "timestamp": time.time(),
            "risk_level": "low",
            "predicted_threats": []
        }

        if anomaly_score > 0.9:
            prediction["risk_level"] = "high"
            prediction["predicted_threats"].append("DDoS_attack")
        elif anomaly_score > 0.7:
            prediction["risk_level"] = "medium"
            prediction["predicted_threats"].append("data_breach")

        if prediction["predicted_threats"]:
            return prediction

        return None

    def _update_threat_intelligence(self, device_id: str, anomaly_score: float):
        """Update global threat intelligence database."""
        threat_key = f"device_{device_id}"

        if threat_key not in self.threat_intelligence:
            self.threat_intelligence[threat_key] = {
                "total_anomalies": 0,
                "avg_score": 0,
                "last_seen": time.time(),
                "threat_patterns": []
            }

        intel = self.threat_intelligence[threat_key]
        intel["total_anomalies"] += 1 if anomaly_score > self.config.anomaly_threshold else 0
        intel["avg_score"] = (intel["avg_score"] + anomaly_score) / 2
        intel["last_seen"] = time.time()

        # Detect patterns
        if anomaly_score > 0.95:
            intel["threat_patterns"].append("critical_anomaly")

    def get_threat_intelligence(self, device_id: str = None) -> Dict[str, Any]:
        """Get threat intelligence data."""
        threat_data = self.threat_intelligence_module.get_threat_intelligence()
        if device_id:
            return self.threat_intelligence.get(f"device_{device_id}", {})

        return {
            "total_devices": len(self.threat_intelligence),
            "high_risk_devices": sum(
                1 for intel in self.threat_intelligence.values()
                if intel["avg_score"] > 0.8
            ),
            "recent_threats": len([
                p for p in self.predictions
                if time.time() - p["timestamp"] < 3600  # Last hour
            ]),
            "external_threat_data": threat_data
        }

    def get_prediction_count(self) -> int:
        """Get total number of predictions made."""
        return len(self.predictions)

    def get_backup_count(self) -> int:
        """Get total number of backup entries."""
        return len(self.backup_data)

    def restore_data(self, device_id: str, hours_back: int = 24) -> List[Dict[str, Any]]:
        """
        Restore backup data for a device.

        Args:
            device_id: Device to restore data for
            hours_back: Hours to look back

        Returns:
            List of backup entries
        """
        cutoff_time = time.time() - (hours_back * 3600)
        return [
            entry for entry in self.backup_data
            if entry["device_id"] == device_id and entry["timestamp"] > cutoff_time
        ]

    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        total_anomalies = sum(
            intel["total_anomalies"] for intel in self.threat_intelligence.values()
        )

        return {
            "report_timestamp": time.time(),
            "total_devices_monitored": len(self.threat_intelligence),
            "total_anomalies_detected": total_anomalies,
            "total_predictions": len(self.predictions),
            "total_backups": len(self.backup_data),
            "system_health": "operational",
            "threat_intelligence_summary": self.get_threat_intelligence()
        }

    def clear_old_data(self, days: int = 30):
        """Clear old backup and prediction data."""
        cutoff_time = time.time() - (days * 24 * 3600)

        self.backup_data = [
            entry for entry in self.backup_data
            if entry["timestamp"] > cutoff_time
        ]

        self.predictions = [
            pred for pred in the self.predictions
            if pred["timestamp"] > cutoff_time
        ]

        self.logger.info(f"Cleared old data older than {days} days")

    def shutdown(self):
        """Shutdown the cloud layer."""
        self.logger.info("Cloud layer shutting down")
        # Could save data to persistent storage here
        pass
