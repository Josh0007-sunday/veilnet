"""
Tests for the Mempool
"""
import pytest
from node.mempool import Mempool
from core.transaction import Transaction, TransactionPayload, TransactionType
from core.signature import SignatureManager
from core.identity import PublicKey
from core.seal import Seal

@pytest.fixture
def mempool():
    """Returns a clean Mempool instance for each test"""
    return Mempool()

@pytest.fixture
def sample_transaction():
    """Returns a sample signed transaction"""
    identity = PublicKey.generate()
    seal = Seal.generate()
    tx = SignatureManager.create_signed_transaction(
        public_key_fingerprint=identity.fingerprint,
        seal=seal,
        payload_type="data",
        payload_data={"message": "mempool test"},
        nonce=0
    )
    return tx

def test_add_and_get_transaction(mempool: Mempool, sample_transaction: Transaction):
    """Test adding a transaction to the mempool and retrieving it."""
    assert mempool.get_size() == 0
    
    # Add transaction
    added = mempool.add_transaction(sample_transaction)
    assert added is True
    assert mempool.get_size() == 1
    
    # Retrieve it
    retrieved_tx = mempool.get_transaction(sample_transaction.transaction_id)
    assert retrieved_tx is not None
    assert retrieved_tx.transaction_id == sample_transaction.transaction_id

def test_add_duplicate_transaction(mempool: Mempool, sample_transaction: Transaction):
    """Test that adding a duplicate transaction fails."""
    mempool.add_transaction(sample_transaction)
    
    # Try to add it again
    added_again = mempool.add_transaction(sample_transaction)
    assert added_again is False
    assert mempool.get_size() == 1

def test_remove_transaction(mempool: Mempool, sample_transaction: Transaction):
    """Test removing a transaction from the mempool."""
    mempool.add_transaction(sample_transaction)
    assert mempool.get_size() == 1
    
    # Remove it
    mempool.remove_transaction(sample_transaction.transaction_id)
    assert mempool.get_size() == 0
    
    # Verify it's gone
    assert mempool.get_transaction(sample_transaction.transaction_id) is None

def test_get_pending_transactions(mempool: Mempool):
    """Test retrieving a list of pending transactions."""
    identity = PublicKey.generate()
    seal = Seal.generate()

    # Create a few transactions
    tx1 = SignatureManager.create_signed_transaction(identity.fingerprint, seal, "data", {"msg": "1"}, 0)
    tx2 = SignatureManager.create_signed_transaction(identity.fingerprint, seal, "data", {"msg": "2"}, 1)
    
    mempool.add_transaction(tx1)
    mempool.add_transaction(tx2)
    
    pending = mempool.get_pending_transactions(limit=5)
    assert len(pending) == 2
    
    # Check that they are sorted by payload timestamp (which is created upon payload instantiation)
    assert pending[0].payload.timestamp <= pending[1].payload.timestamp
