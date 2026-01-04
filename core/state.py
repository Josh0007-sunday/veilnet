"""
State Transition Logic
"""
from typing import Dict, Any, Optional, Set
from dataclasses import dataclass, field
from .transaction import Transaction, TransactionType


@dataclass
class IdentityState:
    """State associated with a PublicKey identity"""
    public_key: str
    balance: int = 0
    active_seals: Set[str] = field(default_factory=set)  # Active seal fingerprints
    all_seals: Set[str] = field(default_factory=set)     # All historical seals
    data_store: Dict[str, Any] = field(default_factory=dict)
    nonce: int = 0
    
    def can_authorize(self, seal_fingerprint: str) -> bool:
        """Check if seal can authorize transactions"""
        return seal_fingerprint in self.active_seals
    
    def add_seal(self, seal_fingerprint: str):
        """Add a new active seal"""
        self.active_seals.add(seal_fingerprint)
        self.all_seals.add(seal_fingerprint)
    
    def rotate_seal(self, old_seal: str, new_seal: str):
        """Rotate from old seal to new seal"""
        if old_seal in self.active_seals:
            self.active_seals.remove(old_seal)
        self.active_seals.add(new_seal)
        self.all_seals.add(new_seal)
    
    def increment_nonce(self):
        """Increment transaction nonce"""
        self.nonce += 1


class StateManager:
    """Manages global state transitions"""
    
    def __init__(self):
        self.identities: Dict[str, IdentityState] = {}
    
    def apply_transaction(self, transaction: Transaction) -> bool:
        """Apply transaction to state"""
        public_key = transaction.public_key
        
        # Get or create identity state
        if public_key not in self.identities:
            self.identities[public_key] = IdentityState(public_key=public_key)
        
        state = self.identities[public_key]
        
        # Check seal authorization
        if not state.can_authorize(transaction.seal_fingerprint):
            return False
        
        # Check nonce
        if transaction.nonce != state.nonce:
            return False
        
        # Apply based on transaction type
        tx_type = transaction.payload.type
        
        if tx_type == TransactionType.TOKEN_TRANSFER:
            # Simple token transfer
            amount = transaction.payload.data.get("amount", 0)
            recipient = transaction.payload.data.get("recipient")
            
            if amount <= 0 or state.balance < amount:
                return False
            
            # Deduct from sender
            state.balance -= amount
            
            # Add to recipient (create if doesn't exist)
            if recipient not in self.identities:
                self.identities[recipient] = IdentityState(public_key=recipient)
            self.identities[recipient].balance += amount
            
        elif tx_type == TransactionType.SEAL_ROTATION:
            # Seal rotation
            old_seal = transaction.payload.data.get("old_seal")
            new_seal = transaction.payload.data.get("new_seal")
            
            if not old_seal or not new_seal:
                return False
            
            state.rotate_seal(old_seal, new_seal)
        
        elif tx_type == TransactionType.DATA:
            # Store data
            for key, value in transaction.payload.data.items():
                state.data_store[key] = value
        
        # Increment nonce
        state.increment_nonce()
        
        return True
    
    def get_identity_state(self, public_key: str) -> Optional[IdentityState]:
        """Get state for a public key"""
        return self.identities.get(public_key)
    
    def initialize_identity(self, public_key: str, initial_seal: str, initial_balance: int = 0):
        """Initialize a new identity"""
        if public_key not in self.identities:
            state = IdentityState(public_key=public_key, balance=initial_balance)
            state.add_seal(initial_seal)
            self.identities[public_key] = state