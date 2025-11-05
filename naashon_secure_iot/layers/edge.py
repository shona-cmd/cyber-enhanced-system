"""
Edge Layer for NaashonSecureIoT.

Handles real-time anomaly detection using ML/DL models at the edge.
NIST CSF Function: Detect (DE)
"""

import logging
from typing import Dict, Any
from ..config import Config
from ..utils.anomaly_detector import IoTAnomalyDetector
from ..utils.federated_learning import FederatedLearning


class EdgeLayer:
    """Edge layer implementation for real-time IoT anomaly detection."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.detector = IoTAnomalyDetector(
            model_path=self.config.ml_model_path,
            threshold=self.config.anomaly_threshold
        )
        self.federated_learning = FederatedLearning()
        self.active_threats = 0
        self.logger.info("Edge layer initialized with anomaly detector")

    def detect_anomaly(self, data: Dict[str, Any]) -> float:
        """
        Detect anomalies in IoT data using ML model.

        Args:
            data: IoT data payload (may be encrypted)

        Returns:
            Anomaly score (0-1)
        """
        try:
            # If data is encrypted, we assume it's been decrypted by
            # network layer
            # For this implementation, we'll work with raw data
            score = self.detector.detect_anomaly(data)

            if score > self.config.anomaly_threshold:
                self.active_threats += 1
                self.logger.warning(f"Anomaly detected with score: {score}")

            return score
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            return 0.0

    def update_model(self, new_model_path: str):
        """Update the ML model with new weights."""
        try:
            self.detector.load_model(new_model_path)
            self.logger.info("ML model updated successfully")
        except Exception as e:
            self.logger.error(f"Model update failed: {e}")

    def train_on_edge(self, data_batch: list, labels: list):
        """Perform federated learning training on edge data."""
        try:
            self.detector.train_model(data_batch, labels, epochs=5)
            self.logger.info("Edge training completed")
        except Exception as e:
            self.logger.error(f"Edge training failed: {e}")

    def federated_update(self, global_model_path: str, local_data: list, local_labels: list):
        """
        Perform federated learning update for low-power optimization.

        Args:
            global_model_path: Path to global model
            local_data: Local training data
            local_labels: Local training labels

        Returns:
            Updated model weights (for aggregation)
        """
        try:
            # Load global model
            self.detector.load_model(global_model_path)

            # Train locally with limited epochs for efficiency
            self.detector.train_model(local_data, local_labels, epochs=3, lr=0.001)

            # Return model weights for federated averaging
            return self.detector.model.state_dict()
        except Exception as e:
            self.logger.error(f"Federated update failed: {e}")
            return None

    def get_active_threats(self) -> int:
        """Get count of currently active threats."""
        return self.active_threats

    def reset_threat_counter(self):
        """Reset the active threats counter."""
        self.active_threats = 0

    def get_model_metrics(self) -> Dict[str, Any]:
        """Get current model performance metrics."""
        return {
            "threshold": self.config.anomaly_threshold,
            "active_threats": self.active_threats,
            "model_loaded": True  # Could be enhanced to check actual model status
        }

    def shutdown(self):
        """Shutdown the edge layer."""
        self.logger.info("Edge layer shutting down")
        # Save model state if needed
        pass
