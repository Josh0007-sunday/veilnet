"""
Test the storage layer
"""
import pytest
from core.identity import PublicKey
from core.seal import Seal
from core.signature import SignatureManager
from core.transaction import TransactionPayload, TransactionType
from storage.db import Database

@pytest.fixture(scope="function")
def db():
    """Fixture to get a clean in-memory database for each test"""
    database = Database(":memory:")
    yield database
    database.close()


def test_storage_operations(db: Database):
    """Test basic storage operations"""
    # 1. Create and save an identity
    identity = PublicKey.generate("ed25519")
    identity_id = db.save_identity(identity)
    assert identity_id is not None
    
    retrieved_identity = db.get_identity(identity.fingerprint)
    assert retrieved_identity is not None
    assert retrieved_identity["public_key_fingerprint"] == identity.fingerprint

    # 2. Authorize a seal
    seal = Seal.generate()
    seal_fingerprint = seal.get_fingerprint()
    seal_public_key_bytes = seal.get_public_key_bytes()
    
    auth_success = db.authorize_seal(
        identity.fingerprint, 
        seal_fingerprint, 
        seal_public_key_bytes
    )
    assert auth_success is True
    
    # Check seal authorization
    retrieved_pk_bytes = db.get_authorized_seal_public_key(
        identity.fingerprint, 
        seal_fingerprint
    )
    assert retrieved_pk_bytes == seal_public_key_bytes
    
    active_seals = db.get_active_seals(identity.fingerprint)
    assert seal_fingerprint in active_seals

    # 3. Create and save a transaction
    transaction = SignatureManager.create_signed_transaction(
        public_key_fingerprint=identity.fingerprint,
        seal=seal,
        payload_type="data",
        payload_data={"message": "Hello VeilNet!"},
        nonce=0
    )
    
    save_success = db.save_transaction(transaction, status="confirmed")
    assert save_success is True
    
    retrieved_tx = db.get_transaction(transaction.transaction_id)
    assert retrieved_tx is not None
    assert retrieved_tx["transaction_id"] == transaction.transaction_id
    assert retrieved_tx["status"] == "confirmed"

    # 4. Check identity state
    state = db.get_identity_state(identity.fingerprint)
    assert state is not None
    assert state["nonce"] == 0
    assert state["balance"] == 0

    # 5. Check database stats
    stats = db.get_database_stats()
    assert stats["identities"] == 1
    assert stats["active_seals"] == 1
    assert stats["transactions"] == {"confirmed": 1}

    # 6. Deactivate seal
    deactivated = db.deactivate_seal(seal_fingerprint)
    assert deactivated is True
    retrieved_pk_after_deactivation = db.get_authorized_seal_public_key(
        identity.fingerprint, 
        seal_fingerprint
    )
    assert retrieved_pk_after_deactivation is None