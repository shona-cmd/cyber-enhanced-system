"""
Network Security utilities for NaashonSecureIoT.

Implements firewall rules, IDS, VPN support, and DDoS protection.
"""

import os
import logging
import subprocess
import time
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import queue

logger = logging.getLogger(__name__)

class FirewallManager:
    """Advanced firewall management with rule-based filtering."""

    def __init__(self, config):
        self.config = config
        self.rules = []
        self.blocked_ips = set()
        self.allowed_ports = set([80, 443, 22])  # Default web and SSH
        self.load_default_rules()

    def load_default_rules(self):
        """Load default firewall rules."""
        self.rules = [
            {
                'name': 'Block suspicious ports',
                'action': 'DROP',
                'protocol': 'TCP',
                'ports': [23, 25, 53, 110, 143, 993, 995],  # Telnet, SMTP, DNS, POP3, IMAP
                'enabled': True
            },
            {
                'name': 'Allow HTTP/HTTPS',
                'action': 'ACCEPT',
                'protocol': 'TCP',
                'ports': [80, 443],
                'enabled': True
            },
            {
                'name': 'Block ICMP flood',
                'action': 'DROP',
                'protocol': 'ICMP',
                'rate_limit': 10,
                'enabled': True
            }
        ]

    def add_rule(self, rule: Dict[str, Any]) -> bool:
        """Add a new firewall rule."""
        required_fields = ['name', 'action', 'protocol']
        if not all(field in rule for field in required_fields):
            return False

        rule['enabled'] = rule.get('enabled', True)
        rule['created_at'] = datetime.now()
        self.rules.append(rule)
        logger.info(f"Firewall rule added: {rule['name']}")
        return True

    def remove_rule(self, rule_name: str) -> bool:
        """Remove a firewall rule."""
        for i, rule in enumerate(self.rules):
            if rule['name'] == rule_name:
                del self.rules[i]
                logger.info(f"Firewall rule removed: {rule_name}")
                return True
        return False

    def block_ip(self, ip_address: str, duration: int = 3600):
        """Block an IP address temporarily."""
        self.blocked_ips.add(ip_address)
        # Schedule unblock
        timer = threading.Timer(duration, self.unblock_ip, args=[ip_address])
        timer.start()
        logger.warning(f"IP blocked: {ip_address} for {duration} seconds")

    def unblock_ip(self, ip_address: str):
        """Unblock an IP address."""
        if ip_address in self.blocked_ips:
            self.blocked_ips.remove(ip_address)
            logger.info(f"IP unblocked: {ip_address}")

    def check_packet(self, packet) -> bool:
        """Check if packet should be allowed based on rules."""
        if not self.config.firewall_enabled:
            return True

        # Check blocked IPs
        if IP in packet and packet[IP].src in self.blocked_ips:
            return False

        # Apply rules
        for rule in self.rules:
            if not rule.get('enabled', False):
                continue

            if self._matches_rule(packet, rule):
                return rule['action'] == 'ACCEPT'

        return False  # Default deny

    def _matches_rule(self, packet, rule) -> bool:
        """Check if packet matches a rule."""
        # Protocol check
        if rule['protocol'] == 'TCP' and TCP not in packet:
            return False
        elif rule['protocol'] == 'UDP' and UDP not in packet:
            return False
        elif rule['protocol'] == 'ICMP' and ICMP not in packet:
            return False

        # Port check
        if 'ports' in rule:
            if TCP in packet and packet[TCP].dport not in rule['ports']:
                return False
            elif UDP in packet and packet[UDP].dport not in rule['ports']:
                return False

        # Rate limit check (simplified)
        if 'rate_limit' in rule:
            # This would need more sophisticated rate limiting
            pass

        return True

    def get_rules(self) -> List[Dict[str, Any]]:
        """Get all firewall rules."""
        return self.rules.copy()

    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IP addresses."""
        return list(self.blocked_ips)


class IntrusionDetectionSystem:
    """Basic IDS with signature-based and anomaly detection."""

    def __init__(self, config):
        self.config = config
        self.signatures = self.load_signatures()
        self.alerts = []
        self.packet_queue = queue.Queue()
        self.running = False

    def load_signatures(self) -> List[Dict[str, Any]]:
        """Load IDS signatures."""
        return [
            {
                'name': 'SYN Flood',
                'pattern': {'flags': 2, 'threshold': 100},  # SYN flag, high frequency
                'severity': 'high',
                'action': 'alert'
            },
            {
                'name': 'Port Scan',
                'pattern': {'unique_ports': 10, 'time_window': 60},
                'severity': 'medium',
                'action': 'alert'
            },
            {
                'name': 'Malformed Packet',
                'pattern': {'invalid_checksum': True},
                'severity': 'low',
                'action': 'log'
            }
        ]

    def start_monitoring(self):
        """Start IDS monitoring."""
        if not self.config.ids_enabled:
            logger.info("IDS disabled in configuration")
            return

        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_packets)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info("IDS monitoring started")

    def stop_monitoring(self):
        """Stop IDS monitoring."""
        self.running = False
        logger.info("IDS monitoring stopped")

    def analyze_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Analyze a packet for security threats."""
        for signature in self.signatures:
            if self._matches_signature(packet, signature):
                alert = {
                    'timestamp': datetime.now(),
                    'signature': signature['name'],
                    'severity': signature['severity'],
                    'source_ip': packet[IP].src if IP in packet else 'unknown',
                    'details': str(packet.summary())
                }
                self.alerts.append(alert)
                logger.warning(f"IDS Alert: {signature['name']} from {alert['source_ip']}")
                return alert
        return None

    def _matches_signature(self, packet, signature) -> bool:
        """Check if packet matches a signature."""
        pattern = signature['pattern']

        if 'flags' in pattern and TCP in packet:
            if packet[TCP].flags != pattern['flags']:
                return False

        if 'invalid_checksum' in pattern:
            if IP in packet and packet[IP].chksum == 0:
                return True

        # Simplified checks - in production, would need more sophisticated analysis
        return False

    def _monitor_packets(self):
        """Monitor network packets."""
        while self.running:
            try:
                # This would integrate with actual packet capture
                # For now, just process queued packets
                if not self.packet_queue.empty():
                    packet = self.packet_queue.get()
                    self.analyze_packet(packet)
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"IDS monitoring error: {e}")

    def get_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent IDS alerts."""
        return self.alerts[-limit:] if self.alerts else []


class DDoSProtection:
    """DDoS protection with rate limiting and traffic analysis."""

    def __init__(self, config):
        self.config = config
        self.ip_rates = {}
        self.blocked_ips = set()
        self.thresholds = {
            'syn_packets': 100,  # per second
            'total_packets': 1000,  # per second
            'unique_ips': 50  # per minute
        }

    def monitor_traffic(self, packet):
        """Monitor traffic for DDoS patterns."""
        if IP not in packet:
            return

        src_ip = packet[IP].src
        current_time = time.time()

        # Initialize IP tracking
        if src_ip not in self.ip_rates:
            self.ip_rates[src_ip] = {
                'packets': [],
                'syn_packets': [],
                'first_seen': current_time
            }

        ip_data = self.ip_rates[src_ip]

        # Track packets
        ip_data['packets'].append(current_time)

        # Track SYN packets
        if TCP in packet and packet[TCP].flags == 2:  # SYN flag
            ip_data['syn_packets'].append(current_time)

        # Clean old data (keep last 60 seconds)
        cutoff = current_time - 60
        ip_data['packets'] = [t for t in ip_data['packets'] if t > cutoff]
        ip_data['syn_packets'] = [t for t in ip_data['syn_packets'] if t > cutoff]

        # Check thresholds
        if len(ip_data['packets']) > self.thresholds['total_packets']:
            self._block_ip(src_ip, "High packet rate DDoS")
        elif len(ip_data['syn_packets']) > self.thresholds['syn_packets']:
            self._block_ip(src_ip, "SYN flood detected")

    def _block_ip(self, ip: str, reason: str):
        """Block an IP address for DDoS protection."""
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            logger.warning(f"DDoS protection: Blocked {ip} - {reason}")

            # Auto-unblock after 1 hour
            timer = threading.Timer(3600, lambda: self.blocked_ips.discard(ip))
            timer.start()

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked."""
        return ip in self.blocked_ips

    def get_stats(self) -> Dict[str, Any]:
        """Get DDoS protection statistics."""
        return {
            'monitored_ips': len(self.ip_rates),
            'blocked_ips': len(self.blocked_ips),
            'thresholds': self.thresholds
        }


class VPNServer:
    """VPN server management for secure remote access."""

    def __init__(self, config):
        self.config = config
        self.connected_clients = {}
        self.server_running = False

    def start_server(self) -> bool:
        """Start VPN server."""
        if not self.config.vpn_required:
            logger.info("VPN not required in configuration")
            return True

        try:
            # This would integrate with OpenVPN or WireGuard
            # For now, just set flag
            self.server_running = True
            logger.info("VPN server started")
            return True
        except Exception as e:
            logger.error(f"Failed to start VPN server: {e}")
            return False

    def stop_server(self):
        """Stop VPN server."""
        self.server_running = False
        logger.info("VPN server stopped")

    def add_client(self, client_id: str, client_config: Dict[str, Any]):
        """Add a VPN client."""
        self.connected_clients[client_id] = {
            'config': client_config,
            'connected_at': datetime.now(),
            'last_seen': datetime.now()
        }
        logger.info(f"VPN client added: {client_id}")

    def remove_client(self, client_id: str):
        """Remove a VPN client."""
        if client_id in self.connected_clients:
            del self.connected_clients[client_id]
            logger.info(f"VPN client removed: {client_id}")

    def get_connected_clients(self) -> List[str]:
        """Get list of connected VPN clients."""
        return list(self.connected_clients.keys())


class NetworkSecurityManager:
    """Central manager for all network security components."""

    def __init__(self, config):
        self.config = config
        self.firewall = FirewallManager(config)
        self.ids = IntrusionDetectionSystem(config)
        self.ddos_protection = DDoSProtection(config)
        self.vpn = VPNServer(config)

    def initialize(self):
        """Initialize all network security components."""
        logger.info("Initializing network security components")

        # Start IDS monitoring
        self.ids.start_monitoring()

        # Start VPN server
        self.vpn.start_server()

        logger.info("Network security components initialized")

    def shutdown(self):
        """Shutdown all network security components."""
        logger.info("Shutting down network security components")

        self.ids.stop_monitoring()
        self.vpn.stop_server()

        logger.info("Network security components shut down")

    def get_status(self) -> Dict[str, Any]:
        """Get status of all security components."""
        return {
            'firewall': {
                'enabled': self.config.firewall_enabled,
                'rules_count': len(self.firewall.rules),
                'blocked_ips': len(self.firewall.blocked_ips)
            },
            'ids': {
                'enabled': self.config.ids_enabled,
                'alerts_count': len(self.ids.alerts),
                'monitoring_active': self.ids.running
            },
            'ddos_protection': self.ddos_protection.get_stats(),
            'vpn': {
                'enabled': self.config.vpn_required,
                'server_running': self.vpn.server_running,
                'connected_clients': len(self.vpn.connected_clients)
            }
        }
