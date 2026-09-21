package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	store "github.com/kaizakin/osto/internal/db"
	"github.com/kaizakin/osto/internal/models"
)

const (
	maxFailedAttempts = 3
	lockoutDuration   = 15 * time.Minute
)

var (
	ErrUsernameTaken    = errors.New("username already taken")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked    = errors.New("account is locked")
)

// RegisterUser validates and creates a new user account.
func RegisterUser(database *sql.DB, username, password string) error {
	if username == "" || password == "" {
		return errors.New("username and password must not be empty")
	}
	existing, err := store.GetUserByUsername(database, username)
	if err != nil {
		return fmt.Errorf("service: register lookup: %w", err)
	}
	if existing != nil {
		return ErrUsernameTaken
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	if _, err := store.CreateUser(database, username, hash); err != nil {
		return fmt.Errorf("service: register create: %w", err)
	}
	return nil
}

// LoginUser authenticates credentials and enforces the lockout policy.
func LoginUser(database *sql.DB, username, password string) (*models.User, error) {
	user, err := store.GetUserByUsername(database, username)
	if err != nil {
		return nil, fmt.Errorf("service: login lookup: %w", err)
	}
	if user == nil {
		return nil, ErrInvalidCredentials
	}
	if user.LockedUntil != nil {
		remaining := time.Until(*user.LockedUntil)
		if remaining > 0 {
			return nil, fmt.Errorf("%w: try again in %s", ErrAccountLocked, remaining.Round(time.Second))
		}
		if err := store.ResetFailedAttempts(database, user.ID); err != nil {
			return nil, err
		}
		user.FailedAttempts = 0
		user.LockedUntil = nil
	}
	if !CheckPassword(user.PasswordHash, password) {
		return nil, handleFailedAttempt(database, user)
	}
	if err := store.ResetFailedAttempts(database, user.ID); err != nil {
		return nil, err
	}
	if err := store.UpdateLastLogin(database, user.ID); err != nil {
		return nil, err
	}
	user, err = store.GetUserByUsername(database, username)
	if err != nil || user == nil {
		return nil, fmt.Errorf("service: reload user: %w", err)
	}
	return user, nil
}

func handleFailedAttempt(database *sql.DB, user *models.User) error {
	newAttempts := user.FailedAttempts + 1
	var lockUntil *time.Time
	if newAttempts >= maxFailedAttempts {
		t := time.Now().UTC().Add(lockoutDuration)
		lockUntil = &t
	}
	if err := store.UpdateFailedAttempts(database, user.ID, newAttempts, lockUntil); err != nil {
		return err
	}
	if lockUntil != nil {
		return fmt.Errorf("%w: account locked for %s due to too many failed attempts",
			ErrAccountLocked, lockoutDuration)
	}
	return fmt.Errorf("%w (%d attempt(s) remaining before lockout)",
		ErrInvalidCredentials, maxFailedAttempts-newAttempts)
}

// NewSession creates and persists a new session for userID with the given timeout.
func NewSession(database *sql.DB, userID int64, timeout time.Duration) (*models.Session, error) {
	id, err := GenerateSessionID()
	if err != nil {
		return nil, err
	}
	session := &models.Session{
		ID:        id,
		UserID:    userID,
		ExpiresAt: time.Now().UTC().Add(timeout),
		CreatedAt: time.Now().UTC(),
	}
	if err := store.CreateSession(database, session); err != nil {
		return nil, fmt.Errorf("service: create session: %w", err)
	}
	return session, nil
}

// ValidateSession returns the session if it exists and has not expired.
func ValidateSession(database *sql.DB, sessionID string) (*models.Session, error) {
	session, err := store.GetSession(database, sessionID)
	if err != nil {
		return nil, fmt.Errorf("service: validate session: %w", err)
	}
	if session == nil || session.IsExpired() {
		if session != nil {
			_ = store.DeleteSession(database, sessionID)
		}
		return nil, nil
	}
	return session, nil
}

// DestroySession deletes a session from the DB.
func DestroySession(database *sql.DB, sessionID string) error {
	if err := store.DeleteSession(database, sessionID); err != nil {
		return fmt.Errorf("service: destroy session: %w", err)
	}
	return nil
}
