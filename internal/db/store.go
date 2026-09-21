package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/kaizakin/osto/internal/models"
)

// CreateUser inserts a new user and returns its ID.
func CreateUser(database *sql.DB, username, passwordHash string) (int64, error) {
	res, err := database.Exec(
		`INSERT INTO users (username, password_hash) VALUES (?, ?)`,
		username, passwordHash,
	)
	if err != nil {
		return 0, fmt.Errorf("store: create user %q: %w", username, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: last insert id: %w", err)
	}
	return id, nil
}

// GetUserByUsername fetches a user by username; returns nil, nil if not found.
func GetUserByUsername(database *sql.DB, username string) (*models.User, error) {
	row := database.QueryRow(`
		SELECT id, username, password_hash, totp_secret, totp_enabled,
		       failed_attempts, locked_until, created_at, last_login_at
		FROM   users WHERE username = ? LIMIT 1`, username)
	return scanUser(row)
}

func scanUser(row *sql.Row) (*models.User, error) {
	u := &models.User{}
	var lockedUntil, lastLoginAt, totpSecret sql.NullString
	var totpEnabled int

	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash,
		&totpSecret, &totpEnabled,
		&u.FailedAttempts, &lockedUntil,
		&u.CreatedAt, &lastLoginAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: scan user: %w", err)
	}

	u.TOTPSecret = totpSecret.String
	u.TOTPEnabled = totpEnabled == 1

	if lockedUntil.Valid {
		t, err := parseFlexibleTime(lockedUntil.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse locked_until: %w", err)
		}
		u.LockedUntil = &t
	}
	if lastLoginAt.Valid {
		t, err := parseFlexibleTime(lastLoginAt.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse last_login_at: %w", err)
		}
		u.LastLoginAt = &t
	}
	return u, nil
}

// UpdateFailedAttempts sets the failed_attempts counter and optional lockout time.
func UpdateFailedAttempts(database *sql.DB, userID int64, attempts int, lockedUntil *time.Time) error {
	var lockStr *string
	if lockedUntil != nil {
		s := lockedUntil.UTC().Format(time.RFC3339)
		lockStr = &s
	}
	if _, err := database.Exec(
		`UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?`,
		attempts, lockStr, userID,
	); err != nil {
		return fmt.Errorf("store: update failed attempts user %d: %w", userID, err)
	}
	return nil
}

// ResetFailedAttempts clears the failed counter and lockout for a user.
func ResetFailedAttempts(database *sql.DB, userID int64) error {
	if _, err := database.Exec(
		`UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?`, userID,
	); err != nil {
		return fmt.Errorf("store: reset failed attempts user %d: %w", userID, err)
	}
	return nil
}

// UpdateLastLogin sets last_login_at to now.
func UpdateLastLogin(database *sql.DB, userID int64) error {
	if _, err := database.Exec(
		`UPDATE users SET last_login_at = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), userID,
	); err != nil {
		return fmt.Errorf("store: update last login user %d: %w", userID, err)
	}
	return nil
}

// SetTOTPSecret stores the TOTP secret and enabled flag for a user.
func SetTOTPSecret(database *sql.DB, userID int64, secret string, enabled bool) error {
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	if _, err := database.Exec(
		`UPDATE users SET totp_secret = ?, totp_enabled = ? WHERE id = ?`,
		secret, enabledInt, userID,
	); err != nil {
		return fmt.Errorf("store: set totp secret user %d: %w", userID, err)
	}
	return nil
}

// CreateSession inserts a new session row.
func CreateSession(database *sql.DB, session *models.Session) error {
	if _, err := database.Exec(
		`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`,
		session.ID, session.UserID, session.ExpiresAt.UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSession retrieves a session by ID; returns nil, nil if not found.
func GetSession(database *sql.DB, sessionID string) (*models.Session, error) {
	row := database.QueryRow(
		`SELECT id, user_id, expires_at, created_at FROM sessions WHERE id = ? LIMIT 1`,
		sessionID,
	)
	s := &models.Session{}
	var expiresAt, createdAt string
	if err := row.Scan(&s.ID, &s.UserID, &expiresAt, &createdAt); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("store: get session: %w", err)
	}
	var err error
	if s.ExpiresAt, err = parseFlexibleTime(expiresAt); err != nil {
		return nil, fmt.Errorf("store: parse expires_at: %w", err)
	}
	if s.CreatedAt, err = parseFlexibleTime(createdAt); err != nil {
		return nil, fmt.Errorf("store: parse created_at: %w", err)
	}
	return s, nil
}

// DeleteSession removes a session by ID.
func DeleteSession(database *sql.DB, sessionID string) error {
	if _, err := database.Exec(`DELETE FROM sessions WHERE id = ?`, sessionID); err != nil {
		return fmt.Errorf("store: delete session %q: %w", sessionID, err)
	}
	return nil
}

// DeleteExpiredSessions removes all sessions past their expiry time.
func DeleteExpiredSessions(database *sql.DB) error {
	if _, err := database.Exec(
		`DELETE FROM sessions WHERE expires_at <= ?`,
		time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("store: delete expired sessions: %w", err)
	}
	return nil
}

func parseFlexibleTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02 15:04:05", s)
}
