"""
Device Layer for NaashonSecureIoT.

Handles IoT device management, encryption, and firmware updates.
NIST CSF Function: Protect (PR)
"""

import logging
from typing import Dict, Any, List
from ..config import Config
from ..utils.encryption import IoTEncryption


class DeviceLayer:
    """Device layer implementation for secure IoT device management."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.encryption = IoTEncryption(self.config)
        self.logger.info("Device layer initialized")

    def add_device(self, device_id: str, device_type: str):
        """Add a new device to the layer."""
        if len(self.devices) >= self.config.max_devices:
            raise ValueError(
                f"Maximum devices ({self.config.max_devices}) reached")

        self.devices[device_id] = {
            "type": device_type,
            "status": "active",
            "firmware_version": "1.0.0",
            "last_seen": None,
            "registered": True
        }
        self.logger.info(f"Device {device_id} added to device layer")

    def remove_device(self, device_id: str):
        """Remove a device from the layer."""
        if device_id in self.devices:
            del self.devices[device_id]
            self.logger.info(f"Device {device_id} removed from device layer")

    def encrypt_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt IoT data before transmission.

        Args:
            data: Raw IoT data

        Returns:
            Encrypted data dictionary
        """
        try:
            encrypted = self.encryption.encrypt_dict(data)
            self.logger.debug("Data encrypted successfully")
            return encrypted
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            return data  # Return unencrypted if encryption fails

    def decrypt_data(self, encrypted_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt received IoT data.

        Args:
            encrypted_data: Encrypted data dictionary

        Returns:
            Decrypted data dictionary
        """
        try:
            decrypted = self.encryption.decrypt_dict(encrypted_data)
            self.logger.debug("Data decrypted successfully")
            return decrypted
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")
            return encrypted_data

    def update_firmware(self, device_id: str, new_version: str):
        """
        Simulate firmware update for a device.

        Args:
            device_id: ID of the device to update
            new_version: New firmware version
        """
        if device_id in self.devices:
            self.devices[device_id]["firmware_version"] = new_version
            self.logger.info(
                f"Firmware updated for device {device_id} to {new_version}")
        else:
            self.logger.warning(
                f"Device {device_id} not found for firmware update")

    def get_device_status(self, device_id: str) -> Dict[str, Any]:
        """Get status of a specific device."""
        return self.devices.get(device_id, {"status": "not_found"})

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Get list of all registered devices."""
        return [{"id": k, **v} for k, v in self.devices.items()]

    def quarantine_device(self, device_id: str):
        """Quarantine a device due to security threat."""
        if device_id in self.devices:
            self.devices[device_id]["status"] = "quarantined"
            self.logger.warning(f"Device {device_id} quarantined")

    def shutdown(self):
        """Shutdown the device layer."""
        self.logger.info("Device layer shutting down")
        # Save device registry if needed
        pass
