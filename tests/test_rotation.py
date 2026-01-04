"""
Tests for Seal Rotation
"""
import pytest
from fastapi.testclient import TestClient

from node.server import app
from core.identity import PublicKey
from core.seal import Seal
from core.transaction import Transaction
from storage.db import Database, get_database

# Get the same test client and fixtures from the API tests
from .test_api import test_db, test_identity_and_seal, client

def test_seal_rotation(test_db: Database, test_identity_and_seal):
    """
    Test the full seal rotation process:
    1. Create and submit a seal rotation transaction.
    2. Verify the old seal is deactivated and the new one is active.
    3. Verify that the old seal can no longer sign transactions.
    4. Verify that the new seal can sign transactions.
    """
    identity, old_seal = test_identity_and_seal
    
    # 1. Create a new seal and the rotation transaction
    new_seal = Seal.generate()
    
    # The nonce for the rotation transaction is 0
    rotation_tx = Transaction.create_seal_rotation(
        public_key_fingerprint=identity.fingerprint,
        old_seal=old_seal,
        new_seal=new_seal,
        nonce=0
    )
    
    # Submit the rotation transaction
    response = client.post("/api/submit", json=rotation_tx.model_dump())
    assert response.status_code == 202, "Seal rotation transaction should be accepted"

    # 2. Verify seal status in the database
    old_seal_pk = test_db.get_authorized_seal_public_key(identity.fingerprint, old_seal.get_fingerprint())
    assert old_seal_pk is None, "Old seal should be deactivated"
    
    new_seal_pk = test_db.get_authorized_seal_public_key(identity.fingerprint, new_seal.get_fingerprint())
    assert new_seal_pk is not None, "New seal should be active"

    # 3. Verify old seal is rejected
    # Nonce is now 1
    tx_with_old_seal = Transaction.create_seal_rotation(
        public_key_fingerprint=identity.fingerprint,
        old_seal=old_seal, # Using the old seal to sign
        new_seal=Seal.generate(), # A dummy new seal
        nonce=1 
    )
    response = client.post("/api/submit", json=tx_with_old_seal.model_dump())
    assert response.status_code == 400, "Transaction signed with old seal should be rejected"

    # 4. Verify new seal is accepted
    # Create a simple data transaction signed with the new seal
    from core.signature import SignatureManager
    data_tx = SignatureManager.create_signed_transaction(
        public_key_fingerprint=identity.fingerprint,
        seal=new_seal,
        payload_type="data",
        payload_data={"message": "First tx with new seal"},
        nonce=1 # Nonce is 1 after the rotation tx
    )
    response = client.post("/api/submit", json=data_tx.model_dump())
    assert response.status_code == 202, "Transaction signed with new seal should be accepted"
    
    # Check that nonce has incremented to 2
    state = test_db.get_identity_state(identity.fingerprint)
    assert state['nonce'] == 2
