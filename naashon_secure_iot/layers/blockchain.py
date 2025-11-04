"""
Blockchain Layer for NaashonSecureIoT.

Implements secure logging and smart contract simulation for tamper-proof records
and automated threat responses.
"""

import logging
import time
import blake3
from typing import Dict, Any, List
from collections import deque
from ..config import Config

logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

class BlockchainEntry:
    """Represents a block in the blockchain."""

    def __init__(self, data: Dict[str, Any], previous_hash: str = "0"):
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """Calculate BLAKE3 hash of the block."""
        data_string = str(self.timestamp) + str(self.data) + self.previous_hash + str(self.nonce)
        return blake3.blake3(data_string.encode()).hexdigest()

    def mine_block(self, difficulty: int = 2):
        """Simple proof-of-work mining."""
        target = 2 ** (256 - difficulty)
        while int(self.hash, 16) > target:
            self.nonce += 1
            self.hash = self.calculate_hash()


class SmartContract:
    """Simple smart contract simulation for automated responses."""

    def __init__(self, contract_id: str):
        self.contract_id = contract_id
        self.conditions = {}
        self.actions = {}
        self.cache = {}  # Initialize cache

    def add_condition(self, condition_name: str, condition_func):
        """Add a condition to the contract."""
        self.conditions[condition_name] = condition_func

    def add_action(self, action_name: str, action_func):
        """Add an action to the contract."""
        self.actions[action_name] = action_func

    def execute(self, data: Dict[str, Any]) -> bool:
        """Execute contract if conditions are met."""
        cache_key = tuple(sorted(data.items()))

        for condition_name, condition in self.conditions.items():
            if condition_name in self.cache and cache_key in self.cache[condition_name]:
                if not self.cache[condition_name][cache_key]:
                    return False
                else:
                    continue
            else:
                condition_result = condition(data)
                if not condition_result:
                    if condition_name not in self.cache:
                        self.cache[condition_name] = {}
                    self.cache[condition_name][cache_key] = False
                    return False
                else:
                    if condition_name not in self.cache:
                        self.cache[condition_name] = {}
                    self.cache[condition_name][cache_key] = True

        for action in self.actions.values():
            action(data)

        return True


class BlockchainLayer:
    """
    Blockchain layer for secure logging and smart contracts.

    Handles blockchain operations such as logging events,
    managing smart contracts, and verifying the integrity of the chain.
    """

    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.chain: deque[BlockchainEntry] = deque(maxlen=1000)
        self.smart_contracts: Dict[str, SmartContract] = {}
        self.difficulty = 2
        self.target_block_time = 10  # Target block creation time in seconds

        self._create_genesis_block()
        self._initialize_smart_contracts()

        self.logger.info(
            "Blockchain layer initialized with genesis block")

    def _create_genesis_block(self):
        """Create the genesis block."""
        genesis_data = {"type": "genesis",
                        "message": "NaashonSecureIoT Blockchain Started"}
        genesis_block = BlockchainEntry(genesis_data)
        genesis_block.mine_block(self.difficulty)
        self.chain.append(genesis_block)

    def _initialize_smart_contracts(self):
        """Initialize default smart contracts for threat response."""
        # Anomaly response contract
        anomaly_contract = SmartContract("anomaly_response")
        anomaly_contract.add_condition("high_anomaly", lambda data: data.get("anomaly_score", 0) > 0.85)
        anomaly_contract.add_action("quarantine_device", lambda data: self._quarantine_device(data.get("device_id")))
        anomaly_contract.add_action("log_threat", lambda data: self.logger.warning(
            f"Threat logged for device {data.get('device_id')}"))

        self.smart_contracts["anomaly_response"] = anomaly_contract

        reg_contract = SmartContract("device_registration")
        reg_contract.add_condition("valid_device", lambda data: bool(data.get("device_id")))
        reg_contract.add_action("register_device", lambda data: self.logger.info(
            f"Device {data.get('device_id')} registered via contract"))

        self.smart_contracts["device_registration"] = reg_contract

    def register_device(self, device_id: str, device_type: str) -> bool:
        """Register device via blockchain.

        Args:
            device_id: Device identifier
            device_type: Type of device

        Returns:
            True if registration successful
        """
        try:
            reg_data = {
                "type": "device_registration",
                "device_id": device_id,
                "device_type": device_type,
                "timestamp": time.time()
            }

            # Execute registration smart contract
            if self.smart_contracts["device_registration"].execute(reg_data):
                self.log_event(reg_data)
                return True

            return False
        except Exception as e:
            self.logger.error(f"Device registration failed: {e}")
            return False

    def log_event(self, event_data: Dict[str, Any]):
        """
        Log an event to the blockchain.

        Args:
            event_data: Event data to log
        """
        try:
            previous_hash = self.chain[-1].hash if self.chain else "0"
            new_block = BlockchainEntry(event_data, previous_hash)
            new_block.mine_block(self.difficulty)
            self.chain.append(new_block)

            self.logger.info(f"Event logged to blockchain: {event_data.get('type', 'unknown')}")

            self._adjust_difficulty()
        except Exception as e:
            self.logger.error(f"Blockchain logging failed: {e}")

    def trigger_response(self, device_id: str, threat_type: str) -> bool:
        """
        Trigger automated response via smart contracts.

        Args:
            device_id: Device identifier
            device_type: Type of device

        Returns:
            True if response triggered
        """
        try:
            response_data = {
                "device_id": device_id,
                "threat_type": threat_type,
                "timestamp": time.time()
            }

            if threat_type == "anomaly":
                return self.smart_contracts["anomaly_response"].execute(response_data)

            # Log the response attempt
            self.log_event({
                "type": "threat_response",
                "device_id": device_id,
                "threat_type": threat_type,
                "response_triggered": True
            })

            return True
        except Exception as e:
            self.logger.error(f"Response trigger failed: {e}")
            return False

    def _quarantine_device(self, device_id: str):
        """Helper method to quarantine device (would integrate with device layer)."""
        self.logger.warning(f"Device {device_id} quarantined via smart contract")

    def _adjust_difficulty(self):
        """Adjust blockchain difficulty based on block creation time."""
        if len(self.chain) < 2:
            return

        # Calculate time taken to create last block
        last_block = self.chain[-1]
        second_last_block = self.chain[-2]
        time_taken = last_block.timestamp - second_last_block.timestamp

        # Adjust difficulty
        if time_taken < self.target_block_time / 2:
            self.difficulty += 1
            self.logger.info(f"Difficulty increased to {self.difficulty}")
        elif time_taken > self.target_block_time * 2:
            self.difficulty = max(1, self.difficulty - 1)  # Ensure difficulty > 0
            self.logger.info(f"Difficulty decreased to {self.difficulty}")

    def verify_chain(self) -> bool:
        """Verify the integrity of the blockchain."""
        self.logger.info("Verifying blockchain integrity...")
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]

            # Check hash integrity
            if current.hash != current.calculate_hash():
                return False

            # Check chain linkage
            if current.previous_hash != previous.hash:
                self.logger.error("Blockchain integrity compromised: previous hash mismatch")
                return False

        self.logger.info("Blockchain integrity verified.")
        return True

    def get_entry_count(self) -> int:
        """Get total number of blockchain entries."""
        self.logger.info("Getting blockchain entry count...")
        return len(self.chain)

    def get_recent_entries(self, count: int = 10) -> List[Dict[str, Any]]:
        """Get recent blockchain entries."""
        self.logger.info(f"Getting recent blockchain entries (count={count})...")
        entries = []
        for block in self.chain[-count:]:
            entries.append({
                "hash": block.hash,
                "timestamp": block.timestamp,
                "data": block.data
            })
        return list(entries)

    def shutdown(self):
        """Shutdown the blockchain layer."""
        self.logger.info("Blockchain layer shutting down")
        # Could save chain to persistent storage here
        pass
