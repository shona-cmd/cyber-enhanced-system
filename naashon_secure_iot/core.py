"""Core module for NaashonSecureIoT framework.

Main orchestrator class that manages the multi-layered
architecture and data flow for IoT cybersecurity
enhancement at MTAC."""
import logging
from typing import Dict, Any
from .config import Config
from .layers.device import DeviceLayer
from .layers.edge import EdgeLayer
from .layers.network import NetworkLayer
from .layers.blockchain import BlockchainLayer
from .layers.cloud import CloudLayer


class NaashonSecureIoT:
    """
    Main framework class for NaashonSecureIoT.

    Orchestrates the five-layer architecture: Device, Edge,
    Network, Blockchain, Cloud. Implements data flow: device
    registration, encrypted transmission, anomaly detection,
    automated response, and continuous monitoring.
    """

    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.config.load_from_env()

        # Initialize logger
        self.logger = logging.getLogger("NaashonSecureIoT")
        self.logger.setLevel(getattr(
            logging, self.config.log_level))
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Initialize layers
        self.device_layer = DeviceLayer(self.config, self.logger)
        self.edge_layer = EdgeLayer(self.config, self.logger)
        self.network_layer = NetworkLayer(self.config, self.logger)
        self.blockchain_layer = BlockchainLayer(self.config, self.logger)
        self.cloud_layer = CloudLayer(self.config, self.logger)

        self.logger.info("NaashonSecureIoT framework initialized for MTAC")

    def register_device(self, device_id: str, device_type: str) -> bool:
        """Register a new IoT device using zero-trust and blockchain.

        Returns:
            bool: True if registration successful"""
        try:
            # Step 1: Zero-trust verification
            if not self.network_layer.verify_device(device_id):
                return False

            # Step 2: Register in blockchain
            if not self.blockchain_layer.register_device(
                    device_id, device_type):
                return False

            # Step 3: Add to device layer
            self.device_layer.add_device(
                device_id, device_type)

            self.logger.info(f"Device {device_id} registered successfully")
            return True
        except Exception as e:
            self.logger.error(
                f"Error registering device {device_id}: {e}")
            return False

    def process_data(self, device_id: str,
                     data: Dict[str, Any]) -> Dict[str, Any]:
        """Process IoT data through the security layers.

        Returns:
            Dict containing processing results and security status
        """
        result = {
            "device_id": device_id,
            "status": "processed",
            "anomaly_detected": False,
            "response_taken": False,
            "blockchain_logged": False
        }

        try:
            # Step 1: Encrypt data
            encrypted_data = self.device_layer.encrypt_data(data)

            # Step 2: Network transmission with segmentation
            # For demo purposes, establish session if needed
            try:
                self.network_layer.establish_session(device_id)
            except ValueError:
                pass  # Session might already exist

            transmitted = self.network_layer.transmit_data(
                device_id, encrypted_data)
            if not transmitted:
                result["status"] = "transmission_failed"
                return result

            # Step 3: Edge anomaly detection
            anomaly_score = self.edge_layer.detect_anomaly(
                encrypted_data)
            if anomaly_score > self.config.anomaly_threshold:
                result["anomaly_detected"] = True
                self.logger.warning(
                    f"Anomaly detected for device {device_id}, "
                    f"score: {anomaly_score}")

                # Step 4: Automated response via smart contracts
                response = self.blockchain_layer.trigger_response(
                    device_id, "anomaly")
                if response:
                    result["response_taken"] = True
                    self.logger.info(
                        f"Automated response triggered for device {device_id}")

            # Step 5: Log to blockchain
            log_entry = {
                "device_id": device_id,
                "timestamp": data.get("timestamp"),
                "anomaly_score": anomaly_score,
                "response": result["response_taken"]
            }
            self.blockchain_layer.log_event(log_entry)
            result["blockchain_logged"] = True

            # Step 6: Cloud analysis and backup
            self.cloud_layer.analyze_and_backup(
                device_id, data, anomaly_score)

            self.logger.info(
                f"Data processed successfully for device {device_id}")
            return result

        except Exception as e:
            self.logger.error(
                f"Error processing data for device {device_id}: {e}")
            result["status"] = "error"
            return result

    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status and metrics."""
        return {
            "mtac_name": self.config.mtac_name,
            "total_devices": len(self.device_layer.devices),
            "active_threats": self.edge_layer.get_active_threats(),
            "blockchain_entries": self.blockchain_layer.get_entry_count(),
            "cloud_predictions": self.cloud_layer.get_prediction_count(),
            "system_health": "operational"  # Could be enhanced
        }

    def shutdown(self):
        """Gracefully shutdown the framework."""
        self.logger.info("Shutting down NaashonSecureIoT framework")
        self.device_layer.shutdown()
        self.edge_layer.shutdown()
        self.network_layer.shutdown()
        self.blockchain_layer.shutdown()
        self.cloud_layer.shutdown()


def main():
    """CLI entry point for the framework."""
    import argparse

    parser = argparse.ArgumentParser(
        description="NaashonSecureIoT Framework")
    parser.add_argument("--config", help="Path to config file")
    parser.add_argument(
        "--demo", action="store_true", help="Run demo mode")

    args = parser.parse_args()

    if args.demo:
        print("Running NaashonSecureIoT demo...")
        print("Demo completed.")
    else:
        print("NaashonSecureIoT framework started. "
              "Use --demo for demonstration.")


if __name__ == "__main__":
    main()
