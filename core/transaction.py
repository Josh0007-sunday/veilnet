"""
Transaction (Sealed Vessel) Schema
"""
from __future__ import annotations
from typing import Any, Dict, TYPE_CHECKING, Optional
from enum import Enum
import json
import time
import base64
from pydantic import BaseModel, Field, ConfigDict, computed_field
import hashlib

if TYPE_CHECKING:
    from .seal import Seal
    from .signature import SignatureManager

class TransactionType(str, Enum):
    """Types of transactions"""
    DATA = "data"
    TOKEN_TRANSFER = "token_transfer"
    SEAL_ROTATION = "seal_rotation"
    CONTRACT_DEPLOY = "contract_deploy"
    CONTRACT_EXECUTE = "contract_execute"

class SealRotationData(BaseModel):
    """Data for a seal rotation transaction."""
    new_seal_fingerprint: str
    new_seal_public_key: str # Base64 encoded public key

class TransactionPayload(BaseModel):
    """Payload carried by transaction"""
    type: TransactionType
    data: Optional[Dict[str, Any]] = Field(default=None)
    encrypted_data: Optional[bytes] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: int = Field(default_factory=lambda: int(time.time()))
    
    def to_bytes(self) -> bytes:
        """Serialize payload to bytes for signing"""
        dump = self.model_dump()
        # Handle bytes serialization for encrypted_data
        if dump.get("encrypted_data"):
            dump["encrypted_data"] = base64.b64encode(dump["encrypted_data"]).decode()
        
        # Exclude None values from the dump to keep it clean
        clean_dump = {k: v for k, v in dump.items() if v is not None}
        
        return json.dumps(clean_dump, sort_keys=True).encode()

class Transaction(BaseModel):
    """
    Sealed Vessel - Core transaction structure
    """
    public_key: str
    seal_fingerprint: str
    payload: TransactionPayload
    signature: str
    nonce: int = 0
    version: str = "1.0"
    
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @computed_field
    @property
    def transaction_id(self) -> str:
        """Compute unique transaction ID from transaction content."""
        content_to_hash = self.to_bytes()
        hash_obj = hashlib.sha256(content_to_hash)
        return f"veiltx:{hash_obj.hexdigest()}"

    def to_bytes(self) -> bytes:
        """Serialize for signing (excludes signature)"""
        data = {
            "public_key": self.public_key,
            "seal_fingerprint": self.seal_fingerprint,
            "payload": self.payload.model_dump(exclude_none=True),
            "nonce": self.nonce,
            "version": self.version
        }
        # Custom handling for payload serialization to match `to_bytes`
        if 'encrypted_data' in data['payload'] and data['payload']['encrypted_data']:
             data['payload']['encrypted_data'] = base64.b64encode(data['payload']['encrypted_data']).decode()

        return json.dumps(data, sort_keys=True).encode()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary including signature and computed fields"""
        return self.model_dump()
    
    @classmethod
    def create_seal_rotation(
        cls, 
        public_key_fingerprint: str, 
        old_seal: 'Seal', 
        new_seal: 'Seal', 
        nonce: int
    ) -> 'Transaction':
        """Helper to create a signed seal rotation transaction."""
        from .signature import SignatureManager
        
        rotation_data = SealRotationData(
            new_seal_fingerprint=new_seal.get_fingerprint(),
            new_seal_public_key=base64.b64encode(new_seal.get_public_key_bytes()).decode()
        )
        
        payload = TransactionPayload(
            type=TransactionType.SEAL_ROTATION,
            data=rotation_data.model_dump()
        )

        unsigned_tx = cls(
            public_key=public_key_fingerprint,
            seal_fingerprint=old_seal.get_fingerprint(),
            payload=payload,
            signature="", # placeholder
            nonce=nonce
        )

        signature = SignatureManager.sign_transaction(old_seal, unsigned_tx.to_bytes())

        return unsigned_tx.model_copy(update={'signature': signature})