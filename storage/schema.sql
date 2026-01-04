-- VeilNet Database Schema
-- SQLite 3.x

-- ==================== CORE TABLES ====================

-- Public Key Identities
CREATE TABLE IF NOT EXISTS identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_fingerprint TEXT UNIQUE NOT NULL,
    public_key_bytes BLOB NOT NULL,
    key_type TEXT NOT NULL CHECK(key_type IN ('rsa', 'ed25519')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Seal Authorizations (links seals to identities)
CREATE TABLE IF NOT EXISTS seal_authorizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id INTEGER NOT NULL,
    seal_fingerprint TEXT UNIQUE NOT NULL,
    seal_public_key_bytes BLOB NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    version INTEGER DEFAULT 1,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deactivated_at TIMESTAMP NULL,
    
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE,
    UNIQUE(identity_id, seal_fingerprint)
);

-- Transactions
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id TEXT UNIQUE NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    seal_fingerprint TEXT NOT NULL,
    payload_type TEXT NOT NULL,
    payload_data TEXT NOT NULL, -- JSON
    metadata TEXT NOT NULL, -- JSON
    signature TEXT NOT NULL,
    nonce INTEGER NOT NULL,
    version TEXT DEFAULT '1.0',
    timestamp INTEGER NOT NULL,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'confirmed', 'rejected')),
    block_height INTEGER NULL,
    confirmed_at TIMESTAMP NULL,
    
    FOREIGN KEY (public_key_fingerprint) REFERENCES identities(public_key_fingerprint)
);

-- Identity State (current balances and data)
CREATE TABLE IF NOT EXISTS identity_state (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id INTEGER UNIQUE NOT NULL,
    balance INTEGER DEFAULT 0,
    nonce INTEGER DEFAULT 0,
    data_store TEXT DEFAULT '{}', -- JSON
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE
);

-- ==================== INDEXES ====================
CREATE INDEX IF NOT EXISTS idx_transactions_public_key ON transactions(public_key_fingerprint);
CREATE INDEX IF NOT EXISTS idx_transactions_seal ON transactions(seal_fingerprint);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_seal_auth_active ON seal_authorizations(is_active, identity_id);
CREATE INDEX IF NOT EXISTS idx_identities_fingerprint ON identities(public_key_fingerprint);

-- ==================== VIEWS ====================

-- Active identities with their state
CREATE VIEW IF NOT EXISTS active_identities AS
SELECT 
    i.public_key_fingerprint,
    i.key_type,
    i.created_at,
    s.balance,
    s.nonce,
    s.data_store,
    (
        SELECT GROUP_CONCAT(sa.seal_fingerprint)
        FROM seal_authorizations sa
        WHERE sa.identity_id = i.id AND sa.is_active = 1
    ) as active_seals
FROM identities i
LEFT JOIN identity_state s ON i.id = s.identity_id
WHERE i.is_active = 1;

-- ==================== TRIGGERS ====================

-- Update last_updated timestamp on identity update
CREATE TRIGGER IF NOT EXISTS update_identity_timestamp 
AFTER UPDATE ON identities
BEGIN
    UPDATE identities SET last_updated = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- Auto-create identity_state when new identity is added
CREATE TRIGGER IF NOT EXISTS create_identity_state 
AFTER INSERT ON identities
BEGIN
    INSERT INTO identity_state (identity_id) VALUES (NEW.id);
END;