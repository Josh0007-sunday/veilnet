"""
Transaction Validator and Processor
"""
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from core.transaction import Transaction, TransactionType, SealRotationData
from storage.db import Database

class Validator:
    """
    Validates and processes incoming transactions against the current state.
    """
    def __init__(self, db: Database):
        self.db = db

    def process_transaction(self, tx: Transaction) -> bool:
        """
        Validates a transaction and applies its effects to the database state.
        Returns True if successful, False otherwise.
        """
        # 1. Perform standard validation for all transaction types
        seal_public_key_bytes = self.db.get_authorized_seal_public_key(
            identity_fingerprint=tx.public_key,
            seal_fingerprint=tx.seal_fingerprint
        )
        if seal_public_key_bytes is None:
            print(f"Validation failed: Seal {tx.seal_fingerprint} not authorized or inactive.")
            return False

        try:
            seal_public_key = serialization.load_pem_public_key(seal_public_key_bytes)
            signature_bytes = base64.b64decode(tx.signature)
            data_to_verify = tx.to_bytes()
            seal_public_key.verify(signature_bytes, data_to_verify)
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False

        current_nonce = self.db.get_identity_nonce(tx.public_key)
        if tx.nonce != current_nonce:
            print(f"Invalid nonce. Expected {current_nonce}, got {tx.nonce}")
            return False
        
        # 2. Apply transaction effects based on type
        if tx.payload.type == TransactionType.SEAL_ROTATION:
            if not self._process_seal_rotation(tx):
                return False
        
        # (Other transaction types would be handled here)

        # 3. Increment nonce for the identity
        self.db.increment_identity_nonce(tx.public_key)
        
        return True

    def _process_seal_rotation(self, tx: Transaction) -> bool:
        """Processes a seal rotation transaction."""
        try:
            rotation_data = SealRotationData.model_validate(tx.payload.data)
            
            # Deactivate the old seal (the one that signed this tx)
            self.db.deactivate_seal(tx.seal_fingerprint)
            
            # Authorize the new seal
            self.db.authorize_seal(
                identity_fingerprint=tx.public_key,
                seal_fingerprint=rotation_data.new_seal_fingerprint,
                seal_public_key_bytes=base64.b64decode(rotation_data.new_seal_public_key) # Decode from base64
            )
            
            print(f"Seal rotated for {tx.public_key}: {tx.seal_fingerprint} -> {rotation_data.new_seal_fingerprint}")
            return True
            
        except Exception as e:
            print(f"Error processing seal rotation: {e}")
            return False
