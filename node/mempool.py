"""
In-memory Mempool for pending transactions.
"""
from typing import Dict, List, Optional
from threading import Lock

from core.transaction import Transaction

class Mempool:
    """
    A simple in-memory mempool to store and manage pending transactions.
    This implementation is thread-safe.
    """
    def __init__(self):
        self._transactions: Dict[str, Transaction] = {}
        self._lock = Lock()

    def add_transaction(self, tx: Transaction) -> bool:
        """
        Adds a transaction to the mempool.
        Returns True if the transaction was added, False if it already exists.
        """
        with self._lock:
            if tx.transaction_id in self._transactions:
                return False
            self._transactions[tx.transaction_id] = tx
            return True

    def get_transaction(self, transaction_id: str) -> Optional[Transaction]:
        """Retrieves a transaction from the mempool by its ID."""
        with self._lock:
            return self._transactions.get(transaction_id)

    def get_pending_transactions(self, limit: int = 100) -> List[Transaction]:
        """Returns a list of pending transactions, up to a given limit."""
        with self._lock:
            # Sort by timestamp to process oldest first
            sorted_txs = sorted(
                self._transactions.values(), 
                key=lambda tx: tx.payload.timestamp
            )
            return sorted_txs[:limit]

    def remove_transaction(self, transaction_id: str):
        """Removes a transaction from the mempool (e.g., after it's been confirmed)."""
        with self._lock:
            if transaction_id in self._transactions:
                del self._transactions[transaction_id]
    
    def get_size(self) -> int:
        """Returns the number of transactions in the mempool."""
        with self._lock:
            return len(self._transactions)

# Singleton instance for the mempool
mempool = Mempool()
