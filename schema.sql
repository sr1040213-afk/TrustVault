
-- TrustVault SQLite reference schema
-- SQLAlchemy models must enforce equivalent constraints.

CREATE TABLE user (
    id INTEGER PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'viewer'
        CHECK (role IN ('admin', 'owner', 'viewer')),
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL
);

CREATE TABLE document (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES user(id),
    title VARCHAR(180) NOT NULL,
    category VARCHAR(80) NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    storage_name VARCHAR(80) NOT NULL UNIQUE,
    sha256 VARCHAR(64) NOT NULL CHECK (length(sha256) = 64),
    size INTEGER NOT NULL CHECK (size >= 0),
    mime_type VARCHAR(120) NOT NULL,
    created_at DATETIME NOT NULL,
    deleted_at DATETIME
);

CREATE TABLE grant (
    id INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES document(id),
    user_id INTEGER NOT NULL REFERENCES user(id),
    permission VARCHAR(10) NOT NULL
        CHECK (permission IN ('read', 'edit')),
    created_at DATETIME NOT NULL,
    revoked_at DATETIME,
    UNIQUE(document_id, user_id)
);

CREATE TABLE audit_event (
    id INTEGER PRIMARY KEY,
    actor_id INTEGER REFERENCES user(id),
    document_id INTEGER REFERENCES document(id),
    action VARCHAR(60) NOT NULL,
    outcome VARCHAR(20) NOT NULL
        CHECK (outcome IN ('success', 'denied', 'error', 'integrity_failure')),
    detail VARCHAR(500) NOT NULL,
    created_at DATETIME NOT NULL,
    previous_mac VARCHAR(64) NOT NULL CHECK (length(previous_mac) = 64),
    event_mac VARCHAR(64) NOT NULL CHECK (length(event_mac) = 64)
);
