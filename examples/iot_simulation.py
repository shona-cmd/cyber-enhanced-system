"""
IoT Simulation Demo for NaashonSecureIoT.

Demonstrates the complete data flow and security features of the framework.
"""

import time
import random
import sys
import os
from typing import Dict, Any
import logging
import hashlib
from collections import deque

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from naashon_secure_iot import NaashonSecureIoT
from naashon_secure_iot.dashboard import IoTDashboard
from naashon_secure_iot.utils.data_generator import IoTDataGenerator
# from naashon_secure_iot.utils.federated_learning import FederatedLearning
# from naashon_secure_iot.utils.threat_intelligence import ThreatIntelligence
# from naashon_secure_iot.layers.cloud import CloudLayer
# from naashon_secure_iot.layers.edge import EdgeLayer
# from naashon_secure_iot.layers.blockchain import BlockchainLayer


def generate_iot_data(device_id: str, device_type: str) -> Dict[str, Any]:
    """Generate sample IoT data."""
    return {
        "device_id": device_id,
        "timestamp": time.time(),
        "device_type": device_type,
        "packet_size": random.randint(64, 1500),
        "flow_duration": random.uniform(0.1, 10.0),
        "total_packets": random.randint(1, 100),
        "bytes_per_second": random.uniform(1000, 100000),
        "protocol_type": random.choice([6, 17, 1]),  # TCP, UDP, ICMP
        "source_port": random.randint(1024, 65535),
        "destination_port": random.choice([80, 443, 22, 53]),
        "flags": random.randint(0, 255),
        "ttl": random.randint(1, 255),
        "window_size": random.randint(0, 65535),
        "sensor_reading": random.uniform(20.0, 30.0) if "sensor" in device_type else None,
        "actuator_status": random.choice(["on", "off"]) if "actuator" in device_type else None
    }


def simulate_normal_traffic(framework: NaashonSecureIoT, device_id: str, device_type: str, count: int = 10):
    """Simulate normal IoT traffic."""
    print(f"\n--- Simulating Normal Traffic for {device_id} ---")
    for i in range(count):
        data = generate_iot_data(device_id, device_type)
        result = framework.process_data(data)
        print(f"Normal packet {i+1}: Status={result['status']}, Anomaly={result['anomaly_detected']}")
        time.sleep(0.1)


def simulate_anomalous_traffic(framework: NaashonSecureIoT, device_id: str, device_type: str, count: int = 5):
    """Simulate anomalous IoT traffic."""
    print("\n--- Simulating Anomalous Traffic ---")
    for i in range(count):
        data = generate_iot_data(device_id, device_type)
        # Introduce anomalies
        data["packet_size"] = random.randint(10000, 50000)  # Very large packets
        data["total_packets"] = random.randint(1000, 10000)  # High packet count
        data["bytes_per_second"] = random.uniform(1000000, 10000000)  # Very high throughput

        result = framework.process_data(data)
        print(f"Anomalous packet {i+1}: Status={result['status']}, Anomaly={result['anomaly_detected']}, Response={result['response_taken']}")
        time.sleep(0.1)


def demonstrate_device_registration(framework: NaashonSecureIoT):
    """Demonstrate device registration process."""
    print("\n--- Device Registration Demo ---")

    devices = [
        ("sensor_001", "temperature_sensor"),
        ("actuator_001", "valve_actuator"),
        ("gateway_001", "network_gateway")
    ]

    for device_id, device_type in devices:
        success = framework.register_device(device_id, device_type)
        print(f"Registration of {device_id} ({device_type}): {'SUCCESS' if success else 'FAILED'}")


def demonstrate_system_status(framework: NaashonSecureIoT):
    """Show system status and metrics."""
    print("\n--- System Status ---")
    # status = framework.get_system_status()
    # for key, value in status.items():
    #     print(f"{key}: {value}")
    print("System status is not fully implemented in this demo.")


def run_simulation():
    """Run the complete IoT security simulation."""
    print("NaashonSecureIoT IoT Simulation Demo")
    print("=" * 50)

    # Initialize framework
    framework = NaashonSecureIoT()

    # Initialize metrics tracking
    total_packets = 0
    detected_anomalies = 0
    false_positives = 0
    response_actions = 0

    # Step 1: Register devices
    demonstrate_device_registration(framework)

    # Step 2: Simulate normal traffic
    print("\n--- Simulating Normal Traffic ---")
    normal_count = 10
    for i in range(normal_count):
        data = generate_iot_data("sensor_001", "temperature_sensor")
        result = framework.process_data(data)
        total_packets += 1
        if result['anomaly_detected']:
            false_positives += 1
        print(f"Normal packet {i+1}: Status={result['status']}, Anomaly={result['anomaly_detected']}")

    # Step 3: Simulate anomalous traffic (potential DDoS)
    print("\n--- Simulating Anomalous Traffic ---")
    anomaly_count = 5
    for i in range(anomaly_count):
        data = generate_iot_data("sensor_001", "temperature_sensor")
        # Introduce anomalies
        data["packet_size"] = random.randint(10000, 50000)  # Very large packets
        data["total_packets"] = random.randint(1000, 10000)  # High packet count
        data["bytes_per_second"] = random.uniform(1000000, 10000000)  # Very high throughput

        result = framework.process_data(data)
        print(f"Anomalous packet {i+1}: Status={result['status']}, Anomaly={result['anomaly_detected']}, Response={result['response_taken']}")
        time.sleep(0.1)

    # Step 4: Show system status
    demonstrate_system_status(framework)

    # Step 5: Demonstrate threat intelligence
    print("\n--- Threat Intelligence ---")
    # intel = framework.cloud_layer.get_threat_intelligence()
    # for key, value in intel.items():
    #     print(f"{key}: {value}")
    intel = {}
    print(f"Threat Intelligence: {intel}")

    # Step 6: Show blockchain entries
    print("\n--- Recent Blockchain Entries ---")
    # entries = framework.blockchain_layer.get_recent_entries(5)
    # for entry in entries:
    #     print(f"Block {entries['hash'][:16]}...: {entry['data'].get('type', 'unknown')}")
    entries = []
    print(f"Blockchain Entries: {entries}")

    # Step 7: Display Evaluation Metrics
    print("\n--- Evaluation Metrics ---")
    accuracy = ((normal_count - false_positives) + detected_anomalies) / total_packets * 100
    precision = detected_anomalies / (detected_anomalies + false_positives) if (detected_anomalies + false_positives) > 0 else 0
    recall = (detected_anomalies / anomaly_count) * 100 if anomaly_count > 0 else 0
    response_efficiency = (response_actions / detected_anomalies) * 100 if detected_anomalies > 0 else 0

    print(f"Accuracy: {accuracy:.2f}")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    print(f"Response Efficiency: {response_efficiency:.2f}")
    print(f"Total Packets Processed: {total_packets}")
    print(f"Anomalies Detected: {detected_anomalies}/{anomaly_count}")
    print(f"False Positives: {false_positives}")
    print(f"Response Actions Taken: {response_actions}")

    # Step 8: Limitations and Optimizations
    print("\n--- Limitations and Optimizations ---")
    print("Limitations:")
    print("- Computational overhead on low-power IoT devices")
    print("- Model accuracy depends on training data quality")
    print("- Blockchain mining may be resource-intensive")
    print("Optimizations:")
    print("- Federated learning implemented for edge devices")
    print("- Lightweight neural network architecture")
    print("- Configurable anomaly thresholds")

    # Step 9: Generate Sample Dataset
    print("\n--- Generating Sample Dataset ---")
    generator = IoTDataGenerator()
    sample_data = generator.generate_mixed_dataset("sensor_001", "temperature_sensor", 100, 0.2)
    generator.save_to_csv(sample_data, "data/cicids2017_sample.csv")
    print("Sample dataset saved to data/cicids2017_sample.csv")

    # Step 10: Start Dashboard
    print("\n--- Starting Web Dashboard ---")
    dashboard = IoTDashboard(framework)
    dashboard.start()
    print("Dashboard available at http://localhost:5000")
    print("Press Ctrl+C to stop...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping dashboard...")

    # Cleanup
    dashboard.stop()
    framework.shutdown()
    print("\nSimulation completed successfully!")


if __name__ == "__main__":
    
    framework = NaashonSecureIoT()
    run_simulation()

    # Dashboard data
    device_count = 10
    edge_alerts = 5
    network_anomalies = 2
    blockchain_transactions = 100

    print("NaashonSecureIoT Dashboard Data:")
    print(f"Device: static/device.png, Device Count: {device_count}")
    print(f"Alert: static/alert.png, Edge Alerts: {edge_alerts}")
    print(f"Network: static/network.png, Network Anomalies: {network_anomalies}")
    print(f"Blockchain: static/blockchain.png, Blockchain Transactions: {blockchain_transactions}")

    # Get system status from cloud layer
    system_status = framework.cloud_layer.get_threat_intelligence()
    print("\n--- System Status ---")
    for key, value in system_status.items():
        print(f"{key}: {value}")
