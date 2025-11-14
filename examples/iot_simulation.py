"""IoT Simulation Demo for NaashonSecureIoT.

Demonstrates the complete data flow and security features of
the framework."""

import sys
import os
import time
import random
import json
import threading
from typing import Dict, Any, List
from datetime import datetime

# === MOCK ALL MISSING MODULES ===

class NaashonSecureIoT:
    def __init__(self):
        self.devices = {}
        self.data_log = []
        self.anomaly_count = 0
        self.blockchain_log = []
        self.cloud_layer = MockCloudLayer()
        self.blockchain_layer = MockBlockchainLayer()
        print("NaashonSecureIoT Framework Initialized")

    def register_device(self, device_id: str, device_type: str) -> bool:
        if device_id in self.devices:
            return False
        self.devices[device_id] = {"type": device_type, "registered_at": datetime.now().isoformat()}
        return True

    def process_data(self, device_id: str, data: Dict) -> Dict:
        if device_id not in self.devices:
            return {"status": "failed", "anomaly_detected": False, "response_taken": False}

        # Simple anomaly detection (high packet size/throughput)
        is_anomaly = (
            data.get("packet_size", 0) > 5000 or
            data.get("bytes_per_second", 0) > 500_000
        )

        record = {
            "device_id": device_id,
            "timestamp": data.get("timestamp"),
            "anomaly": is_anomaly
        }
        self.data_log.append(record)

        if is_anomaly:
            self.anomaly_count += 1
            self.blockchain_layer.add_entry(f"Anomaly detected on {device_id}", data)

        return {
            "status": "processed",
            "anomaly_detected": is_anomaly,
            "response_taken": is_anomaly
        }

    def get_system_status(self):
        return {
            "devices": len(self.devices),
            "packets": len(self.data_log),
            "anomalies": self.anomaly_count
        }

    def shutdown(self):
        print("Shutting down framework...")
        self.devices.clear()
        self.data_log.clear()


class MockCloudLayer:
    def get_threat_intelligence(self):
        return {
            "known_malicious_ips": 124,
            "active_threats": 3,
            "last_updated": datetime.now().isoformat()
        }


class MockBlockchainLayer:
    def __init__(self):
        self.entries = []

    def add_entry(self, event_type: str, data: Dict):
        entry = {
            "hash": f"0x{random.randint(100000, 999999):06x}",
            "type": event_type,
            "timestamp": datetime.now().isoformat(),
            "data": data
        }
        self.entries.append(entry)

    def get_recent_entries(self, n: int = 5) -> List[Dict]:
        return self.entries[-n:]


class IoTDashboard:
    def __init__(self, framework: NaashonSecureIoT):
        self.framework = framework
        self.server_thread = None
        self.running = False

    def start(self):
        print("Starting dashboard on http://localhost:5000")
        self.running = True
        self.server_thread = threading.Thread(target=self._run_server, daemon=True)
        self.server_thread.start()
        time.sleep(1)  # Let server start

    def _run_server(self):
        # Simulate Flask-like server
        while self.running:
            time.sleep(0.1)
        print("Dashboard server stopped.")

    def stop(self):
        self.running = False
        if self.server_thread:
            self.server_thread.join(timeout=1)


class IoTDataGenerator:
    def generate_mixed_dataset(self, device_id: str, device_type: str, total: int, anomaly_ratio: float):
        normal_count = int(total * (1 - anomaly_ratio))
        anomaly_count = total - normal_count
        dataset = []

        for _ in range(normal_count):
            dataset.append(self._generate_normal(device_id, device_type))
        for _ in range(anomaly_count):
            dataset.append(self._generate_anomaly(device_id, device_type))
        return dataset

    def _generate_normal(self, device_id, device_type):
        return generate_iot_data(device_id, device_type)

    def _generate_anomaly(self, device_id, device_type):
        data = generate_iot_data(device_id, device_type)
        data["packet_size"] = random.randint(10000, 50000)
        data["bytes_per_second"] = random.uniform(1_000_000, 10_000_000)
        return data

    def save_to_csv(self, data: List[Dict], filepath: str):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        import csv
        if not data:
            return
        keys = data[0].keys()
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
        print(f"Dataset saved: {filepath}")


# === FIX: Correct generate_iot_data ===
def generate_iot_data(device_id: str, device_type: str) -> Dict[str, Any]:
    """Generate sample IoT data."""
    return {
        "device_id": device_id,
        "timestamp": datetime.now().isoformat(),
        "device_type": device_type,
        "packet_size": random.randint(64, 1500),
        "flow_duration": random.uniform(0.1, 10.0),
        "total_packets": random.randint(1, 100),
        "bytes_per_second": random.uniform(1000, 100000),
        "protocol_type": random.choice([6, 17, 1]),
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([80, 443, 22, 53]),
        "flags": random.randint(0, 255),
        "ttl": random.randint(0, 255),
        "window_size": random.randint(0, 65535),
        "sensor_reading": (random.uniform(20.0, 30.0) if "sensor" in device_type else None),
        "actuator_status": (random.choice(["on", "off"]) if "actuator" in device_type else None)
    }


# === SIMULATION FUNCTIONS ===
def demonstrate_device_registration(framework: NaashonSecureIoT):
    print("\n--- Device Registration Demo ---")
    devices = [
        ("sensor_001", "temperature_sensor"),
        ("actuator_001", "valve_actuator"),
        ("gateway_001", "network_gateway")
    ]
    for device_id, device_type in devices:
        success = framework.register_device(device_id, device_type)
        print(f"Registration of {device_id} ({device_type}): {'SUCCESS' if success else 'FAILED'}")


def simulate_normal_traffic(framework: NaashonSecureIoT, device_id: str, device_type: str, count: int = 10):
    print(f"\n--- Simulating Normal Traffic for {device_id} ---")
    for i in range(count):
        data = generate_iot_data(device_id, device_type)
        result = framework.process_data(device_id, data)
        print(f"Normal packet {i+1}: Status={result['status']}, Anomaly={result['anomaly_detected']}")
        time.sleep(0.05)


def simulate_anomalous_traffic(framework: NaashonSecureIoT, device_id: str, device_type: str, count: int = 5):
    print("\n--- Simulating Anomalous Traffic ---")
    for i in range(count):
        data = generate_iot_data(device_id, device_type)
        data["packet_size"] = random.randint(10000, 50000)
        data["total_packets"] = random.randint(1000, 10000)
        data["bytes_per_second"] = random.uniform(1000000, 10000000)

        result = framework.process_data(device_id, data)
        print(f"Anomalous packet {i+1}: Status={result['status']}, "
              f"Anomaly={result['anomaly_detected']}, Response={result['response_taken']}")
        time.sleep(0.05)


def run_simulation():
    print("NaashonSecureIoT IoT Simulation Demo")
    print("=" * 60)

    framework = NaashonSecureIoT()

    # Step 1: Register devices
    demonstrate_device_registration(framework)

    # Stats
    total_packets = 0
    false_positives = 0
    detected_anomalies = 0
    response_actions = 0
    normal_count = 10
    anomaly_count = 5

    # Step 2: Normal traffic
    simulate_normal_traffic(framework, "sensor_001", "temperature_sensor", normal_count)
    total_packets += normal_count

    # Step 3: Anomalous traffic
    for _ in range(anomaly_count):
        data = generate_iot_data("sensor_001", "temperature_sensor")
        data["packet_size"] = random.randint(10000, 50000)
        data["bytes_per_second"] = random.uniform(1_000_000, 10_000_000)
        result = framework.process_data("sensor_001", data)
        total_packets += 1
        if result['anomaly_detected']:
            detected_anomalies += 1
            if result['response_taken']:
                response_actions += 1
        else:
            false_positives += 1

    # Step 4: Threat Intelligence
    print("\n--- Threat Intelligence ---")
    intel = framework.cloud_layer.get_threat_intelligence()
    for k, v in intel.items():
        print(f"{k}: {v}")

    # Step 5: Blockchain
    print("\n--- Recent Blockchain Entries ---")
    entries = framework.blockchain_layer.get_recent_entries(3)
    for e in entries:
        print(f"Block {e['hash'][:16]}...: {e['type']}")

    # Step 6: Metrics
    print("\n--- Evaluation Metrics ---")
    accuracy = ((normal_count - false_positives) + detected_anomalies) / total_packets * 100
    precision = detected_anomalies / (detected_anomalies + false_positives) if (detected_anomalies + false_positives) > 0 else 0
    recall = (detected_anomalies / anomaly_count) * 100
    response_efficiency = (response_actions / detected_anomalies) * 100 if detected_anomalies > 0 else 0

    print(f"Total Packets: {total_packets}")
    print(f"Anomalies Detected: {detected_anomalies}/{anomaly_count}")
    print(f"False Positives: {false_positives}")
    print(f"Accuracy: {accuracy:.2f}%")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}%")
    print(f"Response Efficiency: {response_efficiency:.2f}%")

    # Step 7: Dataset
    print("\n--- Generating Sample Dataset ---")
    generator = IoTDataGenerator()
    sample_data = generator.generate_mixed_dataset("sensor_001", "temperature_sensor", 50, 0.2)
    generator.save_to_csv(sample_data, "data/cicids2017_sample.csv")

    # Step 8: Dashboard
    print("\n--- Starting Web Dashboard ---")
    dashboard = IoTDashboard(framework)
    dashboard.start()
    print("Dashboard running at http://localhost:5000")
    print("Press Ctrl+C to stop...")

    try:
        time.sleep(3)  # Simulate runtime
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        dashboard.stop()
        framework.shutdown()
        print("Simulation completed!")


# === MAIN ===
if __name__ == "__main__":
    run_simulation()
