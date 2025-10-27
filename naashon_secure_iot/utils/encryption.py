"""
Encryption utilities for NaashonSecureIoT.

Implements AES-256 encryption for secure data transmission in IoT environments.
"""

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Tuple


class IoTEncryption:
    """AES-256 encryption utilities for IoT data security."""

    def __init__(self, password: str = None, key_size: int = 32):
        """
        Initialize encryption with a password-derived key.

        Args:
            password: Password for key derivation (default: generate random)
            key_size: Key size in bytes (32 for AES-256)
        """
        self.key_size = key_size
        self.salt = os.urandom(16)  # 128-bit salt

        if password:
            self.key = self._derive_key(password.encode(), self.salt)
        else:
            self.key = os.urandom(key_size)

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using AES-256-GCM.

        Args:
            plaintext: Data to encrypt

        Returns:
            Tuple of (ciphertext, nonce)
        """
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """
        Decrypt ciphertext using AES-256-GCM.

        Args:
            ciphertext: Encrypted data
            nonce: Nonce used for encryption

        Returns:
            Decrypted plaintext
        """
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def encrypt_dict(self, data: dict) -> dict:
        """
        Encrypt a dictionary of IoT data.

        Args:
            data: Dictionary to encrypt

        Returns:
            Dictionary with encrypted values and metadata
        """
        import json

        plaintext = json.dumps(data).encode('utf-8')
        ciphertext, nonce = self.encrypt(plaintext)

        return {
            "encrypted": True,
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
            "salt": self.salt.hex()
        }

    def decrypt_dict(self, encrypted_data: dict) -> dict:
        """
        Decrypt a dictionary of IoT data.

        Args:
            encrypted_data: Encrypted dictionary

        Returns:
            Decrypted dictionary
        """
        import json

        if not encrypted_data.get("encrypted", False):
            return encrypted_data

        ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
        nonce = bytes.fromhex(encrypted_data["nonce"])

        plaintext = self.decrypt(ciphertext, nonce)
        return json.loads(plaintext.decode('utf-8'))
