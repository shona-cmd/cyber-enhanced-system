import json
from datetime import datetime

# === MOCK: Simulate the missing NaashonSecureIoT framework ===
class NaashonSecureIoT:
    def __init__(self):
        self.devices = {}
        self.data_log = []
        # Initialization complete

    def register_device(self, device_id, device_type):
        if device_id in self.devices:
            return False
        self.devices[device_id] = {
            "type": device_type,
            "registered_at": datetime.now().isoformat()
        }
        return True

    def process_data(self, device_id, data):
        if device_id not in self.devices:
            return {"success": False, "error": "Device not registered"}

        # Validate required fields
        if "timestamp" not in data or "temperature" not in data:
            return {"success": False, "error": "Missing required fields"}

        # Store processed data
        processed = {
            "device_id": device_id,
            "timestamp": data["timestamp"],
            "temperature": data["temperature"],
            "humidity": data.get("humidity"),
            "processed_at": datetime.now().isoformat()
        }
        self.data_log.append(processed)
        return {"success": True, "data": processed}

    def get_system_status(self):
        return {
            "active_devices": len(self.devices),
            "total_data_points": len(self.data_log),
            "status": "operational",
            "uptime": "00:15:23"  # Mocked
        }

    def shutdown(self):
        print(" [INFO] Shutting down NaashonSecureIoT framework...")
        self.devices.clear()
        self.data_log.clear()


# === Original Demo Script (now works with mock) ===
def main():
    """Demo script for NaashonSecureIoT framework."""

    framework = NaashonSecureIoT()

    # Register a device
    device_id = "demo_device"
    device_type = "temperature_sensor"
    if framework.register_device(device_id, device_type):
        print(f"Device {device_id} registered successfully")
    else:
        print(f"Failed to register device {device_id}")

    # Process data
    data = {
        "timestamp": "2025-10-31T12:00:00",
        "temperature": 25.5,
        "humidity": 60.2
    }
    result = framework.process_data(device_id, data)
    print(f"Data processing result: {json.dumps(result, indent=2)}")

    # Get system status
    status = framework.get_system_status()
    print(f"System Status: {json.dumps(status, indent=2)}")

    # Shutdown the framework
    framework.shutdown()
    print("Framework shut down successfully")


if __name__ == "__main__":
    main()