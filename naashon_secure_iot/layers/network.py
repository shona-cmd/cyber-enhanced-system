"""
Network Layer for NaashonSecureIoT.

Implements zero trust architecture, access controls, and secure network
segmentation.
NIST CSF Function: Identify (ID, Protect (PR)
"""

import logging
import time
from typing import Dict, Any, List
from ..config import Config
import requests


class NetworkLayer:
    """Network layer implementation with zero trust and access controls."""

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.trusted_devices: set = set()
        self.network_segments: Dict[str, List[str]] = {}
        self.logger.info("Network layer initialized with zero trust enabled")
        self.ughub_token_url = self.config.ughub_token_url
        self.ughub_api_base = self.config.ughub_api_base
        self.mqtt_broker = self.config.mqtt_broker
        self.mqtt_port = self.config.mqtt_port
        self.ughub_client_id = self.config.ughub_client_id
        self.ughub_client_secret = self.config.ughub_client_secret

    def get_jwt(self) -> str:
        """
        Get JWT token from UGHub.
        Returns:
            JWT token
        """
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.ughub_client_id,
            "client_secret": self.ughub_client_secret
        }
        try:
            r = requests.post(self.ughub_token_url, data=payload)
            r.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
            return r.json()["access_token"]
        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"Failed to obtain JWT token from UGHub: {e}")
            raise

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
            return True

        # Device not trusted - do not auto-add for security
        self.logger.warning(f"Device {device_id} not in trusted list")
        return False

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
        Transmit data through secure network channels via UGHub.

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
                if (info["device_id"] == device_id and
                        self._is_session_valid(session)):
                    active_session = session
                    break

            if not active_session:
                self.logger.warning(
                    f"No valid session for device {device_id}")
                return False

            # Update session activity
            if active_session:
                session = self.active_sessions[session_token]
                session["last_activity"] = time.time()

            # Get JWT token
            token = self.get_jwt()
            headers = {"Authorization": f"Bearer {token}"}

            # Send data to UGHub API gateway
            ughub_api_url = f"{self.ughub_api_base}/devices/data"
            response = requests.post(ughub_api_url, headers=headers,
                                      json=data)
            response.raise_for_status()

            self.logger.debug(
                f"Data transmitted for device {device_id} via UGHub API")
            return True

        except requests.exceptions.RequestException as e:
            self.logger.error(
                f"Transmission failed for device {device_id}: {e}")
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
            "zero_trust_enabled": self.config.zero_trust_enabled,
            "local_ip": self.config.local_ip,
            "subnet_mask": self.config.subnet_mask,
            "default_gateway": self.config.default_gateway,
            "dns_suffix": self.config.dns_suffix,
            "connectivity_status": self._check_connectivity()
        }

    def get_anomaly_count(self) -> int:
        """Get count of network anomalies detected."""
        # For demo purposes, return a simulated count
        # In a real implementation, this would track actual network anomalies
        return 0

    def _check_connectivity(self) -> str:
        """Check connectivity to MTAC network components."""
        try:
            import socket
            # Check if we can reach the gateway
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.config.default_gateway, 80))
            sock.close()
            if result == 0:
                return "connected"
            else:
                return "gateway_unreachable"
        except Exception as e:
            self.logger.warning(f"Connectivity check failed: {e}")
            return "check_failed"

    def shutdown(self):
        """Shutdown the network layer."""
        self.logger.info("Network layer shutting down")
        self.active_sessions.clear()
        self.trusted_devices.clear()
