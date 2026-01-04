"""
SQLite Database Adapter for VeilNet
"""
import sqlite3
import json
from typing import Dict, Any, Optional, List, Tuple
from contextlib import contextmanager
import threading
from pathlib import Path
import logging

from core.identity import PublicKey
from core.transaction import Transaction, TransactionPayload, TransactionType
from core.state import IdentityState

logger = logging.getLogger(__name__)


class Database:
    """Thread-safe SQLite database adapter"""
    
    def __init__(self, db_path: str = "veilnet.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection"""
        if not hasattr(self._local, "connection"):
            self._local.connection = sqlite3.connect(
                self.db_path,
                check_same_thread=False
            )
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection
    
    @contextmanager
    def transaction(self):
        """Context manager for database transactions"""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
    
    def _init_db(self):
        """Initialize database schema"""
        schema_path = Path(__file__).parent / "schema.sql"
        
        with self.transaction() as conn:
            # Read and execute schema
            with open(schema_path, 'r') as f:
                schema_sql = f.read()
            
            conn.executescript(schema_sql)
            logger.info("Database schema initialized")
    
    # ==================== IDENTITY OPERATIONS ====================
    
    def save_identity(self, public_key: PublicKey) -> int:
        """Save a new identity"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                INSERT OR IGNORE INTO identities 
                (public_key_fingerprint, public_key_bytes, key_type)
                VALUES (?, ?, ?)
            """, (
                public_key.fingerprint,
                public_key.key_bytes,
                public_key.key_type
            ))
            
            if cursor.lastrowid is None:
                # Identity already exists, get its ID
                cursor = conn.execute(
                    "SELECT id FROM identities WHERE public_key_fingerprint = ?",
                    (public_key.fingerprint,)
                )
                return cursor.fetchone()["id"]
            
            return cursor.lastrowid
    
    def get_identity(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Get identity by fingerprint"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                SELECT * FROM identities 
                WHERE public_key_fingerprint = ?
            """, (fingerprint,))
            
            row = cursor.fetchone()
            return dict(row) if row else None
    
    # ==================== SEAL OPERATIONS ====================
    
    def authorize_seal(self, identity_fingerprint: str, seal_fingerprint: str, 
                      seal_public_key_bytes: bytes, version: int = 1) -> bool:
        """Authorize a seal for an identity and store its public key."""
        try:
            with self.transaction() as conn:
                cursor = conn.execute(
                    "SELECT id FROM identities WHERE public_key_fingerprint = ?",
                    (identity_fingerprint,)
                )
                identity_row = cursor.fetchone()
                
                if not identity_row:
                    return False
                
                identity_id = identity_row["id"]
                
                conn.execute("""
                    INSERT INTO seal_authorizations 
                    (identity_id, seal_fingerprint, seal_public_key_bytes, version)
                    VALUES (?, ?, ?, ?)
                """, (identity_id, seal_fingerprint, seal_public_key_bytes, version))
                
                return True
        except sqlite3.IntegrityError:
            return False
    
    def deactivate_seal(self, seal_fingerprint: str) -> bool:
        """Deactivate a seal"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                UPDATE seal_authorizations 
                SET is_active = 0, deactivated_at = CURRENT_TIMESTAMP
                WHERE seal_fingerprint = ?
            """, (seal_fingerprint,))
            
            return cursor.rowcount > 0
    
    def get_authorized_seal_public_key(self, identity_fingerprint: str, 
                                       seal_fingerprint: str) -> Optional[bytes]:
        """
        Check if a seal is active and authorized for an identity.
        Returns the seal's public key bytes if it is, otherwise None.
        """
        with self.transaction() as conn:
            cursor = conn.execute("""
                SELECT sa.seal_public_key_bytes
                FROM seal_authorizations sa
                JOIN identities i ON sa.identity_id = i.id
                WHERE i.public_key_fingerprint = ? 
                AND sa.seal_fingerprint = ?
                AND sa.is_active = 1
            """, (identity_fingerprint, seal_fingerprint))
            
            row = cursor.fetchone()
            return row["seal_public_key_bytes"] if row else None
    
    def get_active_seals(self, identity_fingerprint: str) -> List[str]:
        """Get all active seals for an identity"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                SELECT sa.seal_fingerprint
                FROM seal_authorizations sa
                JOIN identities i ON sa.identity_id = i.id
                WHERE i.public_key_fingerprint = ? 
                AND sa.is_active = 1
                ORDER BY sa.version
            """, (identity_fingerprint,))
            
            return [row["seal_fingerprint"] for row in cursor.fetchall()]
    
    # ==================== TRANSACTION OPERATIONS ====================
    
    def save_transaction(self, transaction: Transaction, 
                        status: str = "pending") -> bool:
        """Save a transaction to the database"""
        try:
            with self.transaction() as conn:
                conn.execute("""
                    INSERT INTO transactions 
                    (transaction_id, public_key_fingerprint, seal_fingerprint,
                     payload_type, payload_data, metadata, signature, nonce,
                     version, timestamp, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    transaction.transaction_id,
                    transaction.public_key,
                    transaction.seal_fingerprint,
                    transaction.payload.type.value,
                    json.dumps(transaction.payload.data),
                    json.dumps(transaction.payload.metadata),
                    transaction.signature,
                    transaction.nonce,
                    transaction.version,
                    transaction.payload.timestamp,
                    status
                ))
                
                return True
        except sqlite3.IntegrityError as e:
            logger.error(f"Transaction save failed: {e}")
            return False
    
    def confirm_transaction(self, transaction_id: str, 
                          block_height: Optional[int] = None) -> bool:
        """Mark transaction as confirmed"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                UPDATE transactions 
                SET status = 'confirmed', 
                    confirmed_at = CURRENT_TIMESTAMP,
                    block_height = ?
                WHERE transaction_id = ?
            """, (block_height, transaction_id))
            
            return cursor.rowcount > 0
    
    def get_transaction(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        """Get transaction by ID"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                SELECT * FROM transactions 
                WHERE transaction_id = ?
            """, (transaction_id,))
            
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_pending_transactions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get pending transactions"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                SELECT * FROM transactions 
                WHERE status = 'pending'
                ORDER BY timestamp ASC
                LIMIT ?
            """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_identity_transactions(self, identity_fingerprint: str, 
                                limit: int = 50) -> List[Dict[str, Any]]:
        """Get transactions for an identity"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                SELECT * FROM transactions 
                WHERE public_key_fingerprint = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (identity_fingerprint, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    # ==================== STATE OPERATIONS ====================
    
    def update_identity_state(self, state: IdentityState) -> bool:
        """Update identity state in database"""
        try:
            with self.transaction() as conn:
                # Get identity ID
                cursor = conn.execute(
                    "SELECT id FROM identities WHERE public_key_fingerprint = ?",
                    (state.public_key,)
                )
                identity_row = cursor.fetchone()
                
                if not identity_row:
                    return False
                
                identity_id = identity_row["id"]
                
                # Update state
                conn.execute("""
                    UPDATE identity_state 
                    SET balance = ?, nonce = ?, data_store = ?
                    WHERE identity_id = ?
                """, (
                    state.balance,
                    state.nonce,
                    json.dumps(state.data_store),
                    identity_id
                ))
                
                return True
        except Exception as e:
            logger.error(f"State update failed: {e}")
            return False
    
    def get_identity_state(self, identity_fingerprint: str) -> Optional[Dict[str, Any]]:
        """Get current state of an identity"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                SELECT s.balance, s.nonce, s.data_store
                FROM identity_state s
                JOIN identities i ON s.identity_id = i.id
                WHERE i.public_key_fingerprint = ?
            """, (identity_fingerprint,))
            
            row = cursor.fetchone()
            if row:
                state = dict(row)
                state["data_store"] = json.loads(state["data_store"])
                return state
            return None
    
    # ==================== UTILITY METHODS ====================
    
    def get_identity_nonce(self, identity_fingerprint: str) -> Optional[int]:
        """Get current nonce for an identity"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                SELECT s.nonce
                FROM identity_state s
                JOIN identities i ON s.identity_id = i.id
                WHERE i.public_key_fingerprint = ?
            """, (identity_fingerprint,))
            
            row = cursor.fetchone()
            return row["nonce"] if row else None
    
    def increment_identity_nonce(self, identity_fingerprint: str) -> bool:
        """Increment nonce for an identity"""
        with self.transaction() as conn:
            cursor = conn.execute("""
                UPDATE identity_state 
                SET nonce = nonce + 1
                WHERE identity_id = (
                    SELECT id FROM identities 
                    WHERE public_key_fingerprint = ?
                )
            """, (identity_fingerprint,))
            
            return cursor.rowcount > 0
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self.transaction() as conn:
            stats = {}
            
            # Count identities
            cursor = conn.execute("SELECT COUNT(*) as count FROM identities")
            stats["identities"] = cursor.fetchone()["count"]
            
            # Count active seals
            cursor = conn.execute(
                "SELECT COUNT(*) as count FROM seal_authorizations WHERE is_active = 1"
            )
            stats["active_seals"] = cursor.fetchone()["count"]
            
            # Count transactions by status
            cursor = conn.execute("""
                SELECT status, COUNT(*) as count 
                FROM transactions 
                GROUP BY status
            """)
            stats["transactions"] = {row["status"]: row["count"] 
                                   for row in cursor.fetchall()}
            
            return stats
    
    def close(self):
        """Close all database connections"""
        if hasattr(self._local, "connection"):
            self._local.connection.close()
            delattr(self._local, "connection")

def get_database():
    """Dependency for getting a database instance."""
    db = Database()
    try:
        yield db
    finally:
        db.close()



