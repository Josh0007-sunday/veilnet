"""
Signing and Verification
"""
import base64
import json
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

from core.transaction import Transaction, TransactionPayload, TransactionType
from core.seal import Seal
from core.encryption import PayloadEncryptor


class SignatureManager:
    """Handles transaction signing and verification"""
    
    @staticmethod
    def sign_transaction(seal: Seal, transaction_data: bytes) -> str:
        """Sign transaction data with Seal"""
        signature = seal.sign(transaction_data)
        return base64.b64encode(signature).decode()
    
    @staticmethod
    def create_signed_transaction(
        public_key_fingerprint: str,
        seal: Seal,
        payload_type: str,
        payload_data: dict,
        nonce: int = 0,
        encrypt_payload: bool = False
    ) -> Transaction:
        """Create and sign a transaction in one step, with optional encryption."""
        
        payload: TransactionPayload

        if encrypt_payload and payload_type == TransactionType.DATA:
            # Derive key and encrypt the payload data
            encryption_key = PayloadEncryptor.derive_key_from_seal(seal.export_private())
            
            # Serialize payload data to JSON string then bytes
            payload_bytes = json.dumps(payload_data, sort_keys=True).encode()
            
            encrypted_data = PayloadEncryptor.encrypt(payload_bytes, encryption_key)
            
            payload = TransactionPayload(
                type=TransactionType(payload_type),
                encrypted_data=encrypted_data
            )
        else:
            # Keep payload data in the clear
            payload = TransactionPayload(
                type=TransactionType(payload_type),
                data=payload_data
            )
        
        # 1. Create a transaction with a placeholder signature
        unsigned_tx = Transaction(
            public_key=public_key_fingerprint,
            seal_fingerprint=seal.get_fingerprint(),
            payload=payload,
            signature="",  # Placeholder
            nonce=nonce
        )
        
        # 2. Generate the signature from the unsigned transaction's bytes
        signature = SignatureManager.sign_transaction(
            seal,
            unsigned_tx.to_bytes()
        )
        
        # 3. Create the final, signed transaction by updating the signature
        signed_tx = unsigned_tx.model_copy(update={'signature': signature})
        
        return signed_tx