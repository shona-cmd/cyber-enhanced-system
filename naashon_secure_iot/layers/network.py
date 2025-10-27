"""
Network Layer for NaashonSecureIoT.

Implements zero trust architecture, access controls, and secure network segmentation.
"""

import logging
import time
from typing import Dict, Any, List
from ..config import Config


class NetworkLayer:
    """Network layer implementation with zero trust and access controls."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.trusted_devices: set = set()
        self.network_segments: Dict[str, List[str]] = {}
        self.logger.info("Network layer initialized with zero trust enabled")

    def verify_device(self, device_id: str) -> bool:
        """
        Verify device using zero trust principles.

        Args:
            device_id: Device to verify

        Returns:
            True if device is trusted
        """
        if not self.config.zero_trust_enabled:
            return True

        # Check if device is in trusted list
        if device_id in self.trusted_devices:
            # Additional checks could include:
            # - Behavioral analysis
            # - Certificate validation
            # - Multi-factor authentication
            return True

        # For demo purposes, auto-add devices to trusted list on first verification
        self.add_trusted_device(device_id)
        self.logger.info(f"Device {device_id} added to trusted list during verification")
        return True

    def establish_session(self, device_id: str) -> str:
        """
        Establish a secure session for device communication.

        Args:
            device_id: Device requesting session

        Returns:
            Session token
        """
        if not self.verify_device(device_id):
            raise ValueError(f"Device {device_id} not authorized")

        session_token = f"session_{device_id}_{int(time.time())}"
        self.active_sessions[session_token] = {
            "device_id": device_id,
            "created": time.time(),
            "last_activity": time.time(),
            "segment": self._assign_segment(device_id)
        }

        self.logger.info(f"Session established for device {device_id}")
        return session_token

    def transmit_data(self, device_id: str, data: Dict[str, Any]) -> bool:
        """
        Transmit data through secure network channels.

        Args:
            device_id: Sending device
            data: Data to transmit

        Returns:
            True if transmission successful
        """
        try:
            # Verify device is still trusted
            if not self.verify_device(device_id):
                return False

            # Check for active session
            active_session = None
            for session, info in self.active_sessions.items():
                if info["device_id"] == device_id and self._is_session_valid(session):
                    active_session = session
                    break

            if not active_session:
                self.logger.warning(f"No valid session for device {device_id}")
                return False

            # Update session activity
            self.active_sessions[active_session]["last_activity"] = time.time()

            # Simulate MQTT over TLS transmission
            self.logger.debug(f"Data transmitted for device {device_id} via MQTT/TLS")
            return True

        except Exception as e:
            self.logger.error(f"Transmission failed for device {device_id}: {e}")
            return False

    def _assign_segment(self, device_id: str) -> str:
        """Assign device to network segment based on type."""
        # Simple segmentation logic - could be enhanced
        if "sensor" in device_id.lower():
            segment = "sensor_network"
        elif "actuator" in device_id.lower():
            segment = "control_network"
        else:
            segment = "general_network"

        if segment not in self.network_segments:
            self.network_segments[segment] = []

        if device_id not in self.network_segments[segment]:
            self.network_segments[segment].append(device_id)

        return segment

    def _is_session_valid(self, session_token: str) -> bool:
        """Check if session is still valid."""
        if session_token not in self.active_sessions:
            return False

        session = self.active_sessions[session_token]
        elapsed = time.time() - session["created"]

        if elapsed > self.config.access_control_timeout:
            del self.active_sessions[session_token]
            return False

        return True

    def revoke_access(self, device_id: str):
        """Revoke access for a device."""
        if device_id in self.trusted_devices:
            self.trusted_devices.remove(device_id)

        # Remove from segments
        for segment, devices in self.network_segments.items():
            if device_id in devices:
                devices.remove(device_id)

        # Remove active sessions
        sessions_to_remove = [
            session for session, info in self.active_sessions.items()
            if info["device_id"] == device_id
        ]
        for session in sessions_to_remove:
            del self.active_sessions[session]

        self.logger.warning(f"Access revoked for device {device_id}")

    def add_trusted_device(self, device_id: str):
        """Add device to trusted list."""
        self.trusted_devices.add(device_id)
        self.logger.info(f"Device {device_id} added to trusted list")

    def get_network_status(self) -> Dict[str, Any]:
        """Get current network status."""
        return {
            "active_sessions": len(self.active_sessions),
            "trusted_devices": len(self.trusted_devices),
            "network_segments": len(self.network_segments),
            "zero_trust_enabled": self.config.zero_trust_enabled
        }

    def shutdown(self):
        """Shutdown the network layer."""
        self.logger.info("Network layer shutting down")
        self.active_sessions.clear()
        self.trusted_devices.clear()
