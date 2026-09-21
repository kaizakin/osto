package models

import "time"

type User struct {
	ID             int64
	Username       string
	PasswordHash   string
	TOTPSecret     string
	TOTPEnabled    bool
	FailedAttempts int
	LockedUntil    *time.Time
	CreatedAt      time.Time
	LastLoginAt    *time.Time
}

type Session struct {
	ID        string
	UserID    int64
	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsExpired reports whether the session has passed its expiry time.
func (s *Session) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}

type AppState struct {
	CurrentUser    *User
	ActiveSession  *Session
	SessionTimeout time.Duration
}

// IsLoggedIn returns true when the user holds an active session.
func (a *AppState) IsLoggedIn() bool {
	return a.CurrentUser != nil && a.ActiveSession != nil
}
