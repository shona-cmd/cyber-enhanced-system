"""
Encryption utilities for NaashonSecureIoT.

Implements AES-256 encryption for secure data transmission in IoT environments.
"""

import os
import hashlib
import hmac
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Dict, Any, Optional
import json
import logging

logger = logging.getLogger(__name__)

class KeyManager:
    """Advanced key management with rotation and HSM support."""

    def __init__(self, config):
        self.config = config
        self.current_key = None
        self.key_history = {}
        self.hsm_available = self._check_hsm()

    def _check_hsm(self) -> bool:
        """Check if HSM is available and configured."""
        if not self.config.hsm_enabled or not self.config.hsm_module_path:
            return False
        try:
            # Import HSM module if available
            import PyKCS11
            return True
        except ImportError:
            logger.warning("HSM module not available, using software keys")
            return False

    def generate_key(self, key_id: str = None) -> bytes:
        """Generate a new encryption key."""
        if self.hsm_available:
            # Use HSM for key generation
            return self._generate_hsm_key(key_id)
        else:
            # Use software key generation
            return os.urandom(32)  # 256-bit key

    def _generate_hsm_key(self, key_id: str) -> bytes:
        """Generate key using HSM."""
        # Placeholder for HSM integration
        logger.info(f"Generating key {key_id} using HSM")
        return os.urandom(32)

    def rotate_key(self, old_key_id: str) -> str:
        """Rotate encryption key and maintain history."""
        new_key_id = f"key_{int(datetime.now().timestamp())}"
        new_key = self.generate_key(new_key_id)

        # Store old key for decryption of existing data
        if old_key_id in self.key_history:
            self.key_history[old_key_id]['retirement_date'] = datetime.now()

        self.key_history[new_key_id] = {
            'key': new_key,
            'creation_date': datetime.now(),
            'retirement_date': None
        }

        self.current_key = new_key
        logger.info(f"Key rotated: {old_key_id} -> {new_key_id}")
        return new_key_id

    def get_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve a key by ID."""
        if key_id in self.key_history:
            return self.key_history[key_id]['key']
        return None


class IoTEncryption:
    """Advanced AES-256 encryption utilities for IoT data security with key management."""

    def __init__(self, config):
        """
        Initialize encryption with configuration.

        Args:
            config: Configuration object
        """
        self.config = config
        self.key_manager = KeyManager(config)
        self.key_size = 32  # 256-bit
        self.current_key_id = f"key_{int(datetime.now().timestamp())}"

        # Initialize with current key
        self.current_key = self.key_manager.generate_key(self.current_key_id)
        self.key_manager.key_history[self.current_key_id] = {
            'key': self.current_key,
            'creation_date': datetime.now(),
            'retirement_date': None
        }

        # RSA key pair for digital signatures
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=300000,
            backend=default_backend()
        )
        return kdf.derive(password)

    def encrypt(self, plaintext: bytes, key: bytes = None) -> Tuple[bytes, bytes, bytes, str]:
        """
        Encrypt plaintext using AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            key: Encryption key (uses current key if None)

        Returns:
            Tuple of (ciphertext, nonce, salt, key_id)
        """
        if key is None:
            key = self.current_key
            key_id = self.current_key_id
        else:
            key_id = "custom_key"

        salt = os.urandom(16)  # 128-bit salt
        nonce = os.urandom(12)  # 96-bit nonce for GCM

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return ciphertext, nonce, salt, key_id

    def decrypt(self, ciphertext: bytes, nonce: bytes, salt: bytes, key_id: str) -> bytes:
        """
        Decrypt ciphertext using AES-256-GCM.

        Args:
            ciphertext: Encrypted data
            nonce: Nonce used for encryption
            salt: Salt used for key derivation
            key_id: Key identifier

        Returns:
            Decrypted plaintext
        """
        key = self.key_manager.get_key(key_id)
        if key is None:
            raise ValueError(f"Key {key_id} not found")

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def encrypt_dict(self, data: dict) -> dict:
        """
        Encrypt a dictionary of IoT data with metadata.

        Args:
            data: Dictionary to encrypt

        Returns:
            Dictionary with encrypted values and metadata
        """
        plaintext = json.dumps(data).encode('utf-8')
        ciphertext, nonce, salt, key_id = self.encrypt(plaintext)

        # Create digital signature
        signature = self._sign_data(plaintext)

        return {
            "encrypted": True,
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
            "salt": salt.hex(),
            "key_id": key_id,
            "signature": signature.hex(),
            "timestamp": datetime.now().isoformat(),
            "algorithm": "AES-256-GCM"
        }

    def decrypt_dict(self, encrypted_data: dict) -> dict:
        """
        Decrypt a dictionary of IoT data with integrity verification.

        Args:
            encrypted_data: Encrypted dictionary

        Returns:
            Decrypted dictionary
        """
        if not encrypted_data.get("encrypted", False):
            return encrypted_data

        ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
        nonce = bytes.fromhex(encrypted_data["nonce"])
        salt = bytes.fromhex(encrypted_data["salt"])
        key_id = encrypted_data["key_id"]
        signature = bytes.fromhex(encrypted_data["signature"])

        plaintext = self.decrypt(ciphertext, nonce, salt, key_id)

        # Verify digital signature
        if not self._verify_signature(plaintext, signature):
            raise ValueError("Data integrity check failed")

        return json.loads(plaintext.decode('utf-8'))

    def _sign_data(self, data: bytes) -> bytes:
        """Create digital signature for data integrity."""
        return self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    def _verify_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify digital signature."""
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def homomorphic_encrypt(self, value: float) -> dict:
        """
        Placeholder for homomorphic encryption (privacy-preserving analytics).

        Args:
            value: Numeric value to encrypt

        Returns:
            Encrypted value structure
        """
        # This is a simplified placeholder. Real homomorphic encryption
        # would require specialized libraries like SEAL or HELib
        logger.info("Homomorphic encryption placeholder - using standard encryption")
        return self.encrypt_dict({"value": value})

    def mask_data(self, data: dict, fields_to_mask: list) -> dict:
        """
        Mask sensitive data fields.

        Args:
            data: Data dictionary
            fields_to_mask: List of field names to mask

        Returns:
            Data with masked fields
        """
        masked_data = data.copy()
        for field in fields_to_mask:
            if field in masked_data:
                value = str(masked_data[field])
                if len(value) > 4:
                    masked_data[field] = value[:2] + "*" * (len(value) - 4) + value[-2:]
                else:
                    masked_data[field] = "*" * len(value)
        return masked_data

    def rotate_keys(self):
        """Rotate encryption keys periodically."""
        old_key_id = self.current_key_id
        self.current_key_id = self.key_manager.rotate_key(old_key_id)
        self.current_key = self.key_manager.key_history[self.current_key_id]['key']
        logger.info("Encryption keys rotated successfully")

    def get_key_info(self) -> Dict[str, Any]:
        """Get information about current keys."""
        return {
            "current_key_id": self.current_key_id,
            "key_rotation_days": self.config.key_rotation_days,
            "hsm_enabled": self.key_manager.hsm_available,
            "keys_in_history": len(self.key_manager.key_history)
        }
