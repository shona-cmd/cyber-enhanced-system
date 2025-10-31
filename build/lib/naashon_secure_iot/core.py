"""Core module for NaashonSecureIoT framework.

Main orchestrator class that manages the multi-layered
architecture and data flow for IoT cybersecurity
enhancement at MTAC."""
import logging
from typing import Dict, Any
from .config import Config
from naashon_secure_iot.layers.device import DeviceLayer
from naashon_secure_iot.layers.edge import EdgeLayer
from naashon_secure_iot.layers.network import NetworkLayer
from naashon_secure_iot.layers.blockchain import BlockchainLayer
from naashon_secure_iot.layers.cloud import CloudLayer


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
        log_level = getattr(logging, self.config.log_level)
        self.logger.setLevel(log_level)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - '
                                      '%(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Initialize layers
        self.device_layer = DeviceLayer(self.config, self.logger)
        self.edge_layer = EdgeLayer(self.config, self.logger)
        self.network_layer = NetworkLayer(self.config, self.logger)
        self.blockchain_layer = BlockchainLayer(self.config, self.logger)
        self.cloud_layer = CloudLayer(self.config, self.logger)

        self.logger.info("NaashonSecureIoT framework initialized for MTAC")
        self.logger.debug("Debug logging enabled")

    def register_device(self, device_id: str, device_type: str) -> bool:
        """Register a new IoT device using zero-trust and blockchain.

        Returns:
            bool: True if registration successful"""
        self.logger.info(f"Registering device {device_id} of type {device_type}")
        try:
            # Step 1: Zero-trust verification
            if not self.network_layer.verify_device(device_id):
                self.logger.warning(f"Device {device_id} failed zero-trust verification")
                return False

            # Step 2: Register in blockchain
            if not self.blockchain_layer.register_device(device_id,
                                                        device_type):
                self.logger.warning(
                    f"Device {device_id} failed blockchain registration")
                return False

            # Step 3: Add to device layer
            self.device_layer.add_device(
                device_id, device_type)

            self.logger.info(f"Device {device_id} registered successfully")
            return True
        except Exception as e:
            self.logger.exception(
                f"Error registering device {device_id}: {e}")
            return False

    def process_data(self, device_id: str,
                     data: Dict[str, Any]) -> Dict[str, Any]:
        """Process IoT data through the security layers.

        Returns:
            Dict containing processing results and security status
        """
        self.logger.info(f"Processing data for device {device_id}")
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
            self.logger.debug(f"Data encrypted: {encrypted_data}")

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
                self.logger.warning(f"Data transmission failed for device {device_id}")
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
            self.logger.debug(f"Event logged to blockchain: {log_entry}")

            # Step 6: Cloud analysis and backup
            self.cloud_layer.analyze_and_backup(
                device_id, data, anomaly_score)

            self.logger.info(
                f"Data processed successfully for device {device_id}")
            return result

        except Exception as e:
            self.logger.exception(
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
        self.logger.info("Getting system status")

    def shutdown(self):
        """Gracefully shutdown the framework."""
        self.logger.info("Shutting down NaashonSecureIoT framework")
        self.device_layer.shutdown()
        self.edge_layer.shutdown()
        self.network_layer.shutdown()
        self.blockchain_layer.shutdown()
        self.cloud_layer.shutdown()
        self.logger.info("Framework shutdown complete")


def main():
    """CLI entry point for the framework."""
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="NaashonSecureIoT Framework")
    parser.add_argument("--config", help="Path to config file")
    parser.add_argument(
        "--register_device", nargs=2, metavar=("device_id", "device_type"),
        help="Register a new device")
    parser.add_argument(
        "--process_data", nargs=2, metavar=("device_id", "data_file"),
        help="Process data from a device")
    parser.add_argument(
        "--get_system_status", action="store_true",
        help="Get system status")
    parser.add_argument(
        "--shutdown", action="store_true", help="Shutdown the framework")

    args = parser.parse_args()

    framework = NaashonSecureIoT()

    if args.register_device:
        device_id, device_type = args.register_device
        if framework.register_device(device_id, device_type):
            print(f"Device {device_id} registered successfully")
        else:
            print(f"Failed to register device {device_id}")

    elif args.process_data:
        device_id, data_file = args.process_data
        try:
            with open(data_file, "r") as f:
                data = json.load(f)
            result = framework.process_data(device_id, data)
            print(f"Data processing result: {json.dumps(result)}")
        except FileNotFoundError:
            print(f"Error: Data file {data_file} not found")
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in data file {data_file}")
        except Exception as e:
            print(f"Error processing data: {e}")

    elif args.get_system_status:
        status = framework.get_system_status()
        print(f"System Status: {json.dumps(status)}")

    elif args.shutdown:
        framework.shutdown()
        print("Framework shut down successfully")

    else:
        print("No action specified. Use --help for available options.")

if __name__ == "__main__":
    main()
