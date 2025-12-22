"""
Data generator for NaashonSecureIoT.

Generates synthetic IoT data similar to CICIDS2017 dataset for testing and evaluation.
"""

import random
import time
from typing import List, Dict, Any
import numpy as np


class IoTDataGenerator:
    """
    Synthetic data generator for IoT cybersecurity testing.

    Generates data similar to CICIDS2017 dataset with normal and anomalous traffic patterns.
    """

    def __init__(self, seed: int = 42):
        random.seed(seed)
        np.random.seed(seed)

        # Normal traffic patterns
        self.normal_ranges = {
            'packet_size': (64, 1500),
            'flow_duration': (0.1, 10.0),
            'total_packets': (1, 100),
            'bytes_per_second': (1000, 100000),
            'protocol_type': [6, 17, 1],  # TCP, UDP, ICMP
            'source_port': (1024, 65535),
            'destination_port': [80, 443, 22, 53],
            'flags': (0, 255),
            'ttl': (1, 255),
            'window_size': (0, 65535)
        }

        # Anomalous traffic patterns (DDoS, scans, etc.)
        self.anomaly_patterns = {
            'ddos': {
                'packet_size': (10000, 50000),
                'total_packets': (1000, 10000),
                'bytes_per_second': (1000000, 10000000),
                'flow_duration': (0.01, 0.1)
            },
            'port_scan': {
                'destination_port': list(range(1, 1024)),
                'total_packets': (10, 50),
                'flags': [2, 18]  # SYN, SYN-ACK
            },
            'data_exfiltration': {
                'bytes_per_second': (500000, 2000000),
                'packet_size': (1400, 1500),
                'flow_duration': (30, 300)
            }
        }

    def generate_normal_data(self, device_id: str, device_type: str, count: int = 1) -> List[Dict[str, Any]]:
        """
        Generate normal IoT traffic data.

        Args:
            device_id: Device identifier
            device_type: Type of IoT device
            count: Number of data points to generate

        Returns:
            List of normal data dictionaries
        """
        data_list = []

        for _ in range(count):
            data = {
                "device_id": device_id,
                "timestamp": time.time(),
                "device_type": device_type,
                "packet_size": random.randint(*self.normal_ranges['packet_size']),
                "flow_duration": random.uniform(*self.normal_ranges['flow_duration']),
                "total_packets": random.randint(*self.normal_ranges['total_packets']),
                "bytes_per_second": random.uniform(*self.normal_ranges['bytes_per_second']),
                "protocol_type": random.choice(self.normal_ranges['protocol_type']),
                "source_port": random.randint(*self.normal_ranges['source_port']),
                "destination_port": random.choice(self.normal_ranges['destination_port']),
                "flags": random.randint(*self.normal_ranges['flags']),
                "ttl": random.randint(*self.normal_ranges['ttl']),
                "window_size": random.randint(*self.normal_ranges['window_size']),
                "is_anomaly": False
            }

            # Add device-specific data
            if "sensor" in device_type.lower():
                data["sensor_reading"] = random.uniform(20.0, 30.0)
            elif "actuator" in device_type.lower():
                data["actuator_status"] = random.choice(["on", "off"])

            data_list.append(data)

        return data_list

    def generate_anomalous_data(self, device_id: str, device_type: str,
                               anomaly_type: str, count: int = 1) -> List[Dict[str, Any]]:
        """
        Generate anomalous IoT traffic data.

        Args:
            device_id: Device identifier
            device_type: Type of IoT device
            anomaly_type: Type of anomaly ('ddos', 'port_scan', 'data_exfiltration')
            count: Number of data points to generate

        Returns:
            List of anomalous data dictionaries
        """
        if anomaly_type not in self.anomaly_patterns:
            raise ValueError(f"Unknown anomaly type: {anomaly_type}")

        data_list = []

        for _ in range(count):
            # Start with normal data
            data = self.generate_normal_data(device_id, device_type, 1)[0]
            data["is_anomaly"] = True
            data["anomaly_type"] = anomaly_type

            # Override with anomalous patterns
            pattern = self.anomaly_patterns[anomaly_type]
            for key, value in pattern.items():
                if isinstance(value, list):
                    data[key] = random.choice(value)
                elif isinstance(value, tuple):
                    if isinstance(value[0], int):
                        data[key] = random.randint(*value)
                    else:
                        data[key] = random.uniform(*value)

            data_list.append(data)

        return data_list

    def generate_mixed_dataset(self, device_id: str, device_type: str,
                              total_samples: int, anomaly_ratio: float = 0.1) -> List[Dict[str, Any]]:
        """
        Generate a mixed dataset with normal and anomalous traffic.

        Args:
            device_id: Device identifier
            device_type: Type of IoT device
            total_samples: Total number of samples
            anomaly_ratio: Ratio of anomalous samples (0-1)

        Returns:
            Mixed dataset
        """
        anomaly_count = int(total_samples * anomaly_ratio)
        normal_count = total_samples - anomaly_count

        dataset = []

        # Generate normal data
        dataset.extend(self.generate_normal_data(device_id, device_type, normal_count))

        # Generate anomalous data (mix of types)
        anomaly_types = list(self.anomaly_patterns.keys())
        per_type = anomaly_count // len(anomaly_types)

        for anomaly_type in anomaly_types:
            dataset.extend(self.generate_anomalous_data(device_id, device_type, anomaly_type, per_type))

        # Add remaining anomalies
        remaining = anomaly_count - (per_type * len(anomaly_types))
        if remaining > 0:
            anomaly_type = random.choice(anomaly_types)
            dataset.extend(self.generate_anomalous_data(device_id, device_type, anomaly_type, remaining))

        # Shuffle the dataset
        random.shuffle(dataset)

        return dataset

    def save_to_csv(self, data: List[Dict[str, Any]], filename: str):
        """
        Save generated data to CSV file.

        Args:
            data: Data to save
            filename: Output filename
        """
        import csv

        if not data:
            return

        # Get all possible fieldnames from all data points
        fieldnames = set()
        for item in data:
            fieldnames.update(item.keys())
        fieldnames = sorted(list(fieldnames))

        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)

        print(f"Data saved to {filename}")
