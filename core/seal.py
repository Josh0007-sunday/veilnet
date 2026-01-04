"""
Seal (Authority Object) Management
"""
from dataclasses import dataclass
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import hashlib
import base64
import secrets


@dataclass
class Seal:
    """
    Private authority object for authorizing transactions.
    Never revealed to the network.
    """
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey
    version: int = 1
    is_active: bool = True
    
    @classmethod
    def generate(cls) -> 'Seal':
        """Generate a new Seal"""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)
    
    @classmethod
    def from_seed(cls, seed: bytes) -> 'Seal':
        """Generate Seal from deterministic seed"""
        # Use seed to generate deterministic key
        if len(seed) < 32:
            seed = hashlib.sha256(seed).digest()[:32]
        
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)
    
    def get_fingerprint(self) -> str:
        """
        Generate the Seal Fingerprint (public identifier)
        """
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # Double hash for fingerprint
        first_hash = hashlib.sha256(public_bytes).digest()
        fingerprint_hexdigest = hashlib.sha256(first_hash).hexdigest()
        
        return f"veilseal:{fingerprint_hexdigest[:16]}"
    
    def get_public_key_bytes(self) -> bytes:
        """Exports the public key in PEM format"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign(self, data: bytes) -> bytes:
        """Sign data with the Seal's private key"""
        return self.private_key.sign(data)
    
    def rotate(self) -> Tuple['Seal', 'Seal']:
        """
        Rotate to a new Seal.
        Returns: (old_seal, new_seal)
        """
        old_seal = Seal(
            private_key=self.private_key,
            public_key=self.public_key,
            version=self.version,
            is_active=False  # Old seal becomes inactive
        )
        
        new_seal = Seal.generate()
        new_seal.version = self.version + 1
        
        return old_seal, new_seal
    
    def export_private(self) -> bytes:
        """Export private key bytes (for secure storage)"""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    @classmethod
    def import_private(cls, private_bytes: bytes) -> 'Seal':
        """Import Seal from private key bytes"""
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)