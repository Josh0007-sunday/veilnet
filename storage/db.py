"""
PostgreSQL Database Adapter for VeilNet
"""
import os
import json
import psycopg2
from psycopg2 import extras # To get dictionary-like rows
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
    """Thread-safe PostgreSQL database adapter"""
    
    def __init__(self):
        self._local = threading.local()
        self._init_db()
    
    def _get_connection(self) -> psycopg2.extensions.connection:
        """Get thread-local database connection"""
        if not hasattr(self._local, "connection"):
            self._local.connection = psycopg2.connect(os.environ["DATABASE_URL"])
            self._local.connection.autocommit = False # Manage transactions manually
        return self._local.connection
    
    @contextmanager
    def transaction(self):
        """Context manager for database transactions"""
        conn = self._get_connection()
        cur = None
        try:
            # Create a new cursor that returns results as dictionaries
            cur = conn.cursor(cursor_factory=extras.DictCursor)
            yield cur
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            if cur:
                cur.close()
    
    def _init_db(self):
        """Initialize database schema"""
        schema_path = Path(__file__).parent / "schema.sql"
        
        conn = self._get_connection()
        with conn.cursor() as cur:
            # Read and execute schema
            with open(schema_path, 'r') as f:
                schema_sql = f.read()
            
            cur.execute(schema_sql)
            conn.commit()
            logger.info("Database schema initialized")
    
    # ==================== IDENTITY OPERATIONS ====================
    
    def save_identity(self, public_key: PublicKey) -> int:
        """Save a new identity"""
        with self.transaction() as cur:
            cur.execute("""
                INSERT INTO identities 
                (public_key_fingerprint, public_key_bytes, key_type)
                VALUES (%s, %s, %s)
                ON CONFLICT (public_key_fingerprint) DO NOTHING
                RETURNING id;
            """, (
                public_key.fingerprint,
                public_key.key_bytes,
                public_key.key_type
            ))
            
            # If a row was inserted, return its ID
            pk_id = cur.fetchone()
            if pk_id:
                return pk_id[0]
            
            # If ON CONFLICT DO NOTHING, fetch existing ID
            cur.execute(
                "SELECT id FROM identities WHERE public_key_fingerprint = %s",
                (public_key.fingerprint,)
            )
            return cur.fetchone()[0]
    
    def get_identity(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        """Get identity by fingerprint"""
        with self.transaction() as cur:
            cur.execute("""
                SELECT * FROM identities 
                WHERE public_key_fingerprint = %s
            """, (fingerprint,))
            
            row = cur.fetchone()
            return dict(row) if row else None
    
    # ==================== SEAL OPERATIONS ====================
    
    def authorize_seal(self, identity_fingerprint: str, seal_fingerprint: str, 
                      seal_public_key_bytes: bytes, version: int = 1) -> bool:
        """Authorize a seal for an identity and store its public key."""
        try:
            with self.transaction() as cur:
                cur.execute(
                    "SELECT id FROM identities WHERE public_key_fingerprint = %s",
                    (identity_fingerprint,)
                )
                identity_row = cur.fetchone()
                
                if not identity_row:
                    return False
                
                identity_id = identity_row["id"]
                
                cur.execute("""
                    INSERT INTO seal_authorizations 
                    (identity_id, seal_fingerprint, seal_public_key_bytes, version)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (identity_id, seal_fingerprint) DO NOTHING
                """, (identity_id, seal_fingerprint, seal_public_key_bytes, version))
                
                return cur.rowcount > 0 # Returns 1 if inserted, 0 if conflict
        except psycopg2.IntegrityError: # Specific for PostgreSQL
            return False
    
    def deactivate_seal(self, seal_fingerprint: str) -> bool:
        """Deactivate a seal"""
        with self.transaction() as cur:
            cur.execute("""
                UPDATE seal_authorizations 
                SET is_active = FALSE, deactivated_at = NOW()
                WHERE seal_fingerprint = %s
            """, (seal_fingerprint,))
            
            return cur.rowcount > 0
    
    def get_authorized_seal_public_key(self, identity_fingerprint: str, 
                                       seal_fingerprint: str) -> Optional[bytes]:
        """
        Check if a seal is active and authorized for an identity.
        Returns the seal's public key bytes if it is, otherwise None.
        """
        with self.transaction() as cur:
            cur.execute("""
                SELECT sa.seal_public_key_bytes
                FROM seal_authorizations sa
                JOIN identities i ON sa.identity_id = i.id
                WHERE i.public_key_fingerprint = %s 
                AND sa.seal_fingerprint = %s
                AND sa.is_active = TRUE
            """, (identity_fingerprint, seal_fingerprint))
            
            row = cur.fetchone()
            return row["seal_public_key_bytes"] if row else None
    
    def get_active_seals(self, identity_fingerprint: str) -> List[str]:
        """Get all active seals for an identity"""
        with self.transaction() as cur:
            cur.execute("""
                SELECT sa.seal_fingerprint
                FROM seal_authorizations sa
                JOIN identities i ON sa.identity_id = i.id
                WHERE i.public_key_fingerprint = %s 
                AND sa.is_active = TRUE
                ORDER BY sa.version
            """, (identity_fingerprint,))
            
            return [row["seal_fingerprint"] for row in cur.fetchall()]
    
    # ==================== TRANSACTION OPERATIONS ====================
    
    def save_transaction(self, transaction: Transaction, 
                        status: str = "pending") -> bool:
        """Save a transaction to the database"""
        try:
            with self.transaction() as cur:
                cur.execute("""
                    INSERT INTO transactions 
                    (transaction_id, public_key_fingerprint, seal_fingerprint,
                     payload_type, payload_data, metadata, signature, nonce,
                     version, timestamp, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (transaction_id) DO NOTHING
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
                
                return cur.rowcount > 0
        except psycopg2.IntegrityError as e:
            logger.error(f"Transaction save failed: {e}")
            return False
    
    def confirm_transaction(self, transaction_id: str, 
                          block_height: Optional[int] = None) -> bool:
        """Mark transaction as confirmed"""
        with self.transaction() as cur:
            cur.execute("""
                UPDATE transactions 
                SET status = 'confirmed', 
                    confirmed_at = NOW(),
                    block_height = %s
                WHERE transaction_id = %s
            """, (block_height, transaction_id))
            
            return cur.rowcount > 0
    
    def get_transaction(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        """Get transaction by ID"""
        with self.transaction() as cur:
            cur.execute("""
                SELECT * FROM transactions 
                WHERE transaction_id = %s
            """, (transaction_id,))
            
            row = cur.fetchone()
            return dict(row) if row else None
    
    def get_pending_transactions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get pending transactions"""
        with self.transaction() as cur:
            cur.execute("""
                SELECT * FROM transactions 
                WHERE status = 'pending'
                ORDER BY timestamp ASC
                LIMIT %s
            """, (limit,))
            
            return [dict(row) for row in cur.fetchall()]
    
    def get_identity_transactions(self, identity_fingerprint: str, 
                                limit: int = 50) -> List[Dict[str, Any]]:
        """Get transactions for an identity"""
        with self.transaction() as cur:
            cur.execute("""
                SELECT * FROM transactions 
                WHERE public_key_fingerprint = %s
                ORDER BY timestamp DESC
                LIMIT %s
            """, (identity_fingerprint, limit))
            
            return [dict(row) for row in cur.fetchall()]
    
    # ==================== STATE OPERATIONS ====================
    
    def update_identity_state(self, state: IdentityState) -> bool:
        """Update identity state in database"""
        try:
            with self.transaction() as cur:
                # Get identity ID
                cur.execute(
                    "SELECT id FROM identities WHERE public_key_fingerprint = %s",
                    (state.public_key,)
                )
                identity_row = cur.fetchone()
                
                if not identity_row:
                    return False
                
                identity_id = identity_row["id"]
                
                # Update state
                cur.execute("""
                    UPDATE identity_state 
                    SET balance = %s, nonce = %s, data_store = %s
                    WHERE identity_id = %s
                """, (
                    state.balance,
                    state.nonce,
                    json.dumps(state.data_store),
                    identity_id
                ))
                
                return cur.rowcount > 0
        except Exception as e:
            logger.error(f"State update failed: {e}")
            return False
    
    def get_identity_state(self, identity_fingerprint: str) -> Optional[Dict[str, Any]]:
        """Get current state of an identity"""
        with self.transaction() as cur:
            cur.execute("""
                SELECT s.balance, s.nonce, s.data_store
                FROM identity_state s
                JOIN identities i ON s.identity_id = i.id
                WHERE i.public_key_fingerprint = %s
            """, (identity_fingerprint,))
            
            row = cur.fetchone()
            if row:
                state = dict(row)
                state["data_store"] = json.loads(state["data_store"])
                return state
            return None
    
    # ==================== UTILITY METHODS ====================
    
    def get_identity_nonce(self, identity_fingerprint: str) -> Optional[int]:
        """Get current nonce for an identity"""
        with self.transaction() as cur:
            cur.execute("""
                SELECT s.nonce
                FROM identity_state s
                JOIN identities i ON s.identity_id = i.id
                WHERE i.public_key_fingerprint = %s
            """, (identity_fingerprint,))
            
            row = cur.fetchone()
            return row["nonce"] if row else None
    
    def increment_identity_nonce(self, identity_fingerprint: str) -> bool:
        """Increment nonce for an identity"""
        with self.transaction() as cur:
            cur.execute("""
                UPDATE identity_state 
                SET nonce = nonce + 1
                WHERE identity_id = (
                    SELECT id FROM identities 
                    WHERE public_key_fingerprint = %s
                )
            """, (identity_fingerprint,))
            
            return cur.rowcount > 0
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self.transaction() as cur:
            stats = {}
            
            # Count identities
            cur.execute("SELECT COUNT(*) as count FROM identities")
            stats["identities"] = cur.fetchone()["count"]
            
            # Count active seals
            cur.execute(
                "SELECT COUNT(*) as count FROM seal_authorizations WHERE is_active = TRUE"
            )
            stats["active_seals"] = cur.fetchone()["count"]
            
            # Count transactions by status
            cur.execute("""
                SELECT status, COUNT(*) as count 
                FROM transactions 
                GROUP BY status
            """)
            stats["transactions"] = {row["status"]: row["count"] 
                                   for row in cur.fetchall()}
            
            return stats
    
    def close(self):
        """Close all database connections"""
        if hasattr(self._local, "connection") and self._local.connection:
            self._local.connection.close()
            delattr(self._local, "connection")

def get_database():
    """Dependency for getting a database instance."""
    db = Database()
    try:
        yield db
    finally:
        db.close()
