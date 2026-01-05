-- VeilNet Database Schema
-- PostgreSQL

-- ==================== CORE TABLES ====================

-- Public Key Identities
CREATE TABLE IF NOT EXISTS identities (
    id SERIAL PRIMARY KEY,
    public_key_fingerprint TEXT UNIQUE NOT NULL,
    public_key_bytes BYTEA NOT NULL,
    key_type VARCHAR(20) NOT NULL CHECK(key_type IN ('rsa', 'ed25519')),
    created_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    last_updated TIMESTAMP DEFAULT NOW()
);

-- Seal Authorizations (links seals to identities)
CREATE TABLE IF NOT EXISTS seal_authorizations (
    id SERIAL PRIMARY KEY,
    identity_id INTEGER NOT NULL,
    seal_fingerprint TEXT NOT NULL,
    seal_public_key_bytes BYTEA NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    version INTEGER DEFAULT 1,
    added_at TIMESTAMP DEFAULT NOW(),
    deactivated_at TIMESTAMP NULL,
    
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE,
    UNIQUE(identity_id, seal_fingerprint) -- Seal fingerprint is unique per identity
);

-- Transactions
CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    transaction_id TEXT UNIQUE NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    seal_fingerprint TEXT NOT NULL,
    payload_type TEXT NOT NULL,
    payload_data JSONB NOT NULL, -- Changed to JSONB for efficiency
    metadata JSONB NOT NULL, -- Changed to JSONB
    signature TEXT NOT NULL,
    nonce INTEGER NOT NULL,
    version TEXT DEFAULT '1.0',
    timestamp BIGINT NOT NULL, -- Use BIGINT for UNIX timestamp
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'confirmed', 'rejected')),
    block_height INTEGER NULL,
    confirmed_at TIMESTAMP NULL,
    
    FOREIGN KEY (public_key_fingerprint) REFERENCES identities(public_key_fingerprint)
);

-- Identity State (current balances and data)
CREATE TABLE IF NOT EXISTS identity_state (
    id SERIAL PRIMARY KEY,
    identity_id INTEGER UNIQUE NOT NULL,
    balance BIGINT DEFAULT 0, -- Balance can be large
    nonce INTEGER DEFAULT 0,
    data_store JSONB DEFAULT '{}'::jsonb, -- Changed to JSONB with default casting
    updated_at TIMESTAMP DEFAULT NOW(),
    
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE
);

-- ==================== INDEXES ====================
CREATE INDEX IF NOT EXISTS idx_transactions_public_key ON transactions(public_key_fingerprint);
CREATE INDEX IF NOT EXISTS idx_transactions_seal ON transactions(seal_fingerprint);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_seal_auth_active ON seal_authorizations(is_active, identity_id);
CREATE INDEX IF NOT EXISTS idx_identities_fingerprint ON identities(public_key_fingerprint);

-- ==================== FUNCTIONS AND TRIGGERS ====================

-- Function to update last_updated timestamp on identity update
CREATE OR REPLACE FUNCTION update_identity_timestamp_func()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_identity_timestamp
BEFORE UPDATE ON identities
FOR EACH ROW
EXECUTE FUNCTION update_identity_timestamp_func();

-- Function to auto-create identity_state when new identity is added
CREATE OR REPLACE FUNCTION create_identity_state_func()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO identity_state (identity_id) VALUES (NEW.id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER create_identity_state
AFTER INSERT ON identities
FOR EACH ROW
EXECUTE FUNCTION create_identity_state_func();

-- ==================== VIEWS ====================

-- Active identities with their state
CREATE OR REPLACE VIEW active_identities AS
SELECT 
    i.public_key_fingerprint,
    i.key_type,
    i.created_at,
    s.balance,
    s.nonce,
    s.data_store,
    (
        SELECT STRING_AGG(sa.seal_fingerprint, ',')
        FROM seal_authorizations sa
        WHERE sa.identity_id = i.id AND sa.is_active = TRUE
    ) as active_seals
FROM identities i
LEFT JOIN identity_state s ON i.id = s.identity_id
WHERE i.is_active = TRUE;
