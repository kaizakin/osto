package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/kaizakin/osto/internal/db/sqlcgen"
	"github.com/kaizakin/osto/internal/models"
)

func queries(database *sql.DB) *sqlcgen.Queries {
	return sqlcgen.New(database)
}

func ctx() context.Context {
	return context.Background()
}

// CreateUser inserts a new user and returns its ID.
func CreateUser(database *sql.DB, username, passwordHash string) (int64, error) {
	id, err := queries(database).CreateUser(ctx(), sqlcgen.CreateUserParams{
		Username:     username,
		PasswordHash: passwordHash,
	})
	if err != nil {
		return 0, fmt.Errorf("store: create user %q: %w", username, err)
	}
	return id, nil
}

// GetUserByUsername fetches a user by username; returns nil, nil if not found.
func GetUserByUsername(database *sql.DB, username string) (*models.User, error) {
	row, err := queries(database).GetUserByUsername(ctx(), username)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get user %q: %w", username, err)
	}
	user, err := userFromSQLC(row)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateFailedAttempts sets the failed_attempts counter and optional lockout time.
func UpdateFailedAttempts(database *sql.DB, userID int64, attempts int, lockedUntil *time.Time) error {
	if err := queries(database).UpdateFailedAttempts(ctx(), sqlcgen.UpdateFailedAttemptsParams{
		FailedAttempts: int64(attempts),
		LockedUntil:    formatOptionalRFC3339(lockedUntil),
		ID:             userID,
	}); err != nil {
		return fmt.Errorf("store: update failed attempts user %d: %w", userID, err)
	}
	return nil
}

// ResetFailedAttempts clears the failed counter and lockout for a user.
func ResetFailedAttempts(database *sql.DB, userID int64) error {
	if err := queries(database).ResetFailedAttempts(ctx(), userID); err != nil {
		return fmt.Errorf("store: reset failed attempts user %d: %w", userID, err)
	}
	return nil
}

// UpdateLastLogin sets last_login_at to now.
func UpdateLastLogin(database *sql.DB, userID int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	if err := queries(database).UpdateLastLogin(ctx(), sqlcgen.UpdateLastLoginParams{
		LastLoginAt: &now,
		ID:          userID,
	}); err != nil {
		return fmt.Errorf("store: update last login user %d: %w", userID, err)
	}
	return nil
}

// SetTOTPSecret stores the TOTP secret and enabled flag for a user.
func SetTOTPSecret(database *sql.DB, userID int64, secret string, enabled bool) error {
	if err := queries(database).SetTOTPSecret(ctx(), sqlcgen.SetTOTPSecretParams{
		TotpSecret:  secret,
		TotpEnabled: enabled,
		ID:          userID,
	}); err != nil {
		return fmt.Errorf("store: set totp secret user %d: %w", userID, err)
	}
	return nil
}

// CreateSession inserts a new session row.
func CreateSession(database *sql.DB, session *models.Session) error {
	if err := queries(database).CreateSession(ctx(), sqlcgen.CreateSessionParams{
		ID:        session.ID,
		UserID:    session.UserID,
		ExpiresAt: session.ExpiresAt.UTC().Format(time.RFC3339),
	}); err != nil {
		return fmt.Errorf("store: create session: %w", err)
	}
	return nil
}

// GetSession retrieves a session by ID; returns nil, nil if not found.
func GetSession(database *sql.DB, sessionID string) (*models.Session, error) {
	row, err := queries(database).GetSession(ctx(), sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: get session: %w", err)
	}
	session, err := sessionFromSQLC(row)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// DeleteSession removes a session by ID.
func DeleteSession(database *sql.DB, sessionID string) error {
	if err := queries(database).DeleteSession(ctx(), sessionID); err != nil {
		return fmt.Errorf("store: delete session %q: %w", sessionID, err)
	}
	return nil
}

// DeleteExpiredSessions removes all sessions past their expiry time.
func DeleteExpiredSessions(database *sql.DB) error {
	if err := queries(database).DeleteExpiredSessions(ctx(), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("store: delete expired sessions: %w", err)
	}
	return nil
}

func userFromSQLC(row sqlcgen.User) (*models.User, error) {
	createdAt, err := parseFlexibleTime(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse created_at: %w", err)
	}
	lockedUntil, err := parseOptionalTime(row.LockedUntil)
	if err != nil {
		return nil, fmt.Errorf("store: parse locked_until: %w", err)
	}
	lastLoginAt, err := parseOptionalTime(row.LastLoginAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse last_login_at: %w", err)
	}
	return &models.User{
		ID:             row.ID,
		Username:       row.Username,
		PasswordHash:   row.PasswordHash,
		TOTPSecret:     row.TotpSecret,
		TOTPEnabled:    row.TotpEnabled,
		FailedAttempts: int(row.FailedAttempts),
		LockedUntil:    lockedUntil,
		CreatedAt:      createdAt,
		LastLoginAt:    lastLoginAt,
	}, nil
}

func sessionFromSQLC(row sqlcgen.Session) (*models.Session, error) {
	expiresAt, err := parseFlexibleTime(row.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse expires_at: %w", err)
	}
	createdAt, err := parseFlexibleTime(row.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse created_at: %w", err)
	}
	return &models.Session{
		ID:        row.ID,
		UserID:    row.UserID,
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
	}, nil
}

func formatOptionalRFC3339(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

func parseOptionalTime(s *string) (*time.Time, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	t, err := parseFlexibleTime(*s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func parseFlexibleTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02 15:04:05", s)
}
