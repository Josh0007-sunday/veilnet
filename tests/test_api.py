"""
Tests for the VeilNet Node API
"""
import pytest
from fastapi.testclient import TestClient
import os

from node.server import app
from core.identity import PublicKey
from core.seal import Seal
from core.signature import SignatureManager
from storage.db import Database, get_database
from core.transaction import Transaction

TEST_DB_PATH = "test_api.db"

@pytest.fixture(scope="module")
def test_db():
    """
    Module-scoped fixture to set up and tear down a test database.
    It creates a DB instance, overrides the app's dependency, and cleans up afterward.
    """
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    
    db_instance = Database(TEST_DB_PATH)
    
    def override_get_database():
        yield db_instance

    app.dependency_overrides[get_database] = override_get_database
    
    yield db_instance
    
    db_instance.close()
    app.dependency_overrides.clear()
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)


@pytest.fixture(scope="function") # Changed to function scope for isolation
def test_identity_and_seal(test_db: Database):
    """Fixture to create a fresh identity and seal for each test function"""
    # Clean up tables before each test
    with test_db.transaction() as conn:
        conn.execute("DELETE FROM identities")
        conn.execute("DELETE FROM seal_authorizations")
        conn.execute("DELETE FROM transactions")
        conn.execute("DELETE FROM identity_state")

    identity = PublicKey.generate("ed25519")
    seal = Seal.generate()
    
    test_db.save_identity(identity)
    test_db.authorize_seal(
        identity.fingerprint, 
        seal.get_fingerprint(),
        seal.get_public_key_bytes()
    )
    
    return identity, seal

client = TestClient(app)

def test_root_endpoint(test_db):
    """Test the root endpoint"""
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "message": "VeilNet node is running"}

def test_submit_and_query_mempool(test_identity_and_seal, test_db: Database):
    """Test submitting a valid transaction and then querying it from the mempool."""
    identity, seal = test_identity_and_seal
    
    transaction = SignatureManager.create_signed_transaction(
        public_key_fingerprint=identity.fingerprint,
        seal=seal,
        payload_type="data",
        payload_data={"message": "API test"},
        nonce=0
    )
    
    response = client.post("/api/submit", json=transaction.model_dump())
    assert response.status_code == 202
    
    # Query the transaction endpoint, which should find it in the mempool
    tx_id = transaction.transaction_id
    response = client.get(f"/api/transaction/{tx_id}")
    
    assert response.status_code == 200
    retrieved_tx = response.json()
    
    # The response should be the model dump of the transaction from the mempool
    assert retrieved_tx == transaction.model_dump()


def test_submit_invalid_nonce(test_identity_and_seal):
    """Test that submitting a transaction with an incorrect nonce fails"""
    identity, seal = test_identity_and_seal
    
    # Try to submit with nonce 1 (should be 0)
    transaction = SignatureManager.create_signed_transaction(
        public_key_fingerprint=identity.fingerprint,
        seal=seal,
        payload_type="data",
        payload_data={"message": "Invalid nonce"},
        nonce=1
    )
    
    response = client.post("/api/submit", json=transaction.model_dump())
    assert response.status_code == 400
    assert "processing failed" in response.json()["detail"].lower()

def test_submit_multiple_transactions(test_identity_and_seal, test_db: Database):
    """Test submitting multiple transactions sequentially"""
    identity, seal = test_identity_and_seal

    # First transaction (nonce 0)
    tx1 = SignatureManager.create_signed_transaction(
        public_key_fingerprint=identity.fingerprint,
        seal=seal,
        payload_type="data",
        payload_data={"message": "First tx"},
        nonce=0
    )
    res1 = client.post("/api/submit", json=tx1.model_dump())
    assert res1.status_code == 202

    # Check nonce is now 1
    assert test_db.get_identity_nonce(identity.fingerprint) == 1

    # Second transaction (nonce 1)
    tx2 = SignatureManager.create_signed_transaction(
        public_key_fingerprint=identity.fingerprint,
        seal=seal,
        payload_type="data",
        payload_data={"message": "Second tx"},
        nonce=1
    )
    res2 = client.post("/api/submit", json=tx2.model_dump())
    assert res2.status_code == 202
    
    # Check nonce is now 2
    assert test_db.get_identity_nonce(identity.fingerprint) == 2

def test_get_identity_state(test_identity_and_seal):
    """Test retrieving the state of an identity"""
    identity, _ = test_identity_and_seal
    
    response = client.get(f"/api/state/{identity.fingerprint}")
    
    assert response.status_code == 200
    state = response.json()
    assert state["nonce"] == 0
    assert state["balance"] == 0
