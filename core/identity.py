"""
PublicKey Identity Management
"""
from dataclasses import dataclass
from typing import ClassVar
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives import serialization
import hashlib
import base64


@dataclass(frozen=True)
class PublicKey:
    """
    Stable public identifier that defines an identity namespace.
    Immutable after creation.
    """
    
    # Supported key types
    KEY_TYPES: ClassVar[dict] = {
        "rsa": rsa.RSAPublicKey,
        "ed25519": ed25519.Ed25519PublicKey
    }
    
    key_bytes: bytes
    key_type: str
    fingerprint: str
    
    @classmethod
    def generate(cls, key_type: str = "ed25519") -> 'PublicKey':
        """
        Generate a new PublicKey identity
        """
        if key_type == "ed25519":
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
        elif key_type == "rsa":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
        else:
            raise ValueError(f"Unsupported key type: {key_type}")
        
        # Serialize to bytes
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Generate fingerprint
        fingerprint = cls._generate_fingerprint(key_bytes)
        
        return cls(
            key_bytes=key_bytes,
            key_type=key_type,
            fingerprint=fingerprint
        )
    
    @staticmethod
    def _generate_fingerprint(key_bytes: bytes) -> str:
        """Generate SHA256 fingerprint of public key"""
        hash_obj = hashlib.sha256(key_bytes)
        return f"veilpk:{hash_obj.hexdigest()[:16]}"
    
    @classmethod
    def from_bytes(cls, key_bytes: bytes, key_type: str) -> 'PublicKey':
        """Create PublicKey from serialized bytes"""
        fingerprint = cls._generate_fingerprint(key_bytes)
        return cls(
            key_bytes=key_bytes,
            key_type=key_type,
            fingerprint=fingerprint
        )
    
    def verify(self) -> bool:
        """Verify the public key is valid"""
        try:
            if self.key_type == "ed25519":
                ed25519.Ed25519PublicKey.from_public_bytes(
                    self._get_raw_bytes()
                )
            elif self.key_type == "rsa":
                serialization.load_pem_public_key(self.key_bytes)
            return True
        except Exception:
            return False
    
    def _get_raw_bytes(self) -> bytes:
        """Extract raw key bytes from PEM"""
        # This is a simplified extraction
        lines = self.key_bytes.decode().split('\n')
        key_data = ''.join(lines[1:-2])
        return base64.b64decode(key_data)
    
    def __str__(self) -> str:
        return self.fingerprint