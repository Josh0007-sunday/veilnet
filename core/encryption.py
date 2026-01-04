"""
Payload Encryption Management
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class PayloadEncryptor:
    """Handles encryption and decryption of transaction payloads."""

    SALT_SIZE = 16
    TAG_SIZE = 16
    NONCE_SIZE = 12

    @staticmethod
    def derive_key_from_seal(seal_private_key_bytes: bytes) -> bytes:
        """
        Derives a stable 32-byte encryption key from a Seal's private key using HKDF.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'veilnet-encryption-salt', # A constant salt for this use case
            info=b'payload-encryption-key',
            backend=default_backend()
        )
        return hkdf.derive(seal_private_key_bytes)

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """
        Encrypts data using AES-256-GCM.
        Returns a byte string in the format: nonce || ciphertext || tag
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(PayloadEncryptor.NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        # The tag is appended to the ciphertext by AESGCM
        return nonce + ciphertext

    @staticmethod
    def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
        """
        Decrypts data encrypted with AES-256-GCM.
        Expects a byte string in the format: nonce || ciphertext || tag
        """
        if len(encrypted_data) < PayloadEncryptor.NONCE_SIZE + PayloadEncryptor.TAG_SIZE:
            raise ValueError("Invalid encrypted data format.")
            
        nonce = encrypted_data[:PayloadEncryptor.NONCE_SIZE]
        ciphertext_with_tag = encrypted_data[PayloadEncryptor.NONCE_SIZE:]
        
        aesgcm = AESGCM(key)
        
        try:
            return aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        except Exception as e:
            raise ValueError(f"Decryption failed. The data may be corrupt or the key incorrect. Error: {e}")
