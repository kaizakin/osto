-- schema.sql: SQLite table definitions for the auth-cli application.
-- Applied once at startup via internal/db/db.go if tables do not yet exist.

-- users: stores registered accounts, password hashes, TOTP config, and lockout state.
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER  PRIMARY KEY AUTOINCREMENT,
    username        TEXT     UNIQUE NOT NULL,
    password_hash   TEXT     NOT NULL,
    totp_secret     TEXT     NOT NULL DEFAULT '',
    totp_enabled    BOOLEAN  NOT NULL DEFAULT 0,
    failed_attempts INTEGER  NOT NULL DEFAULT 0,
    locked_until    DATETIME NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at   DATETIME NULL
);

-- sessions: stores SHA-256 digests of session tokens with expiry.
-- id is hex(SHA-256(raw 32-byte token)). The raw token never hits this table.
CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT     PRIMARY KEY,
    user_id     INTEGER  NOT NULL,
    expires_at  DATETIME NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
