package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	bcryptCost        = 12
	sessionTokenBytes = 32
)

// HashPassword returns a bcrypt hash of password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}
	return string(hash), nil
}

// CheckPassword reports whether plaintext matches the bcrypt hash.
func CheckPassword(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

// GenerateTOTPSecret generates a new RFC 6238 TOTP key for username.
func GenerateTOTPSecret(username string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "osto",
		AccountName: username,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      otp.DigitsSix,
		Period:      30,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: generate TOTP secret: %w", err)
	}
	return key, nil
}

// ValidateTOTPCode returns true if code is currently valid for secret.
func ValidateTOTPCode(secret, code string) bool {
	return totp.Validate(code, secret)
}

// GenerateSessionID returns a cryptographically secure 256-bit hex token.
// This is the raw bearer token for CLI memory only. Persist HashSessionToken(id).
func GenerateSessionID() (string, error) {
	b := make([]byte, sessionTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generate session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashSessionToken returns the hex SHA-256 of the 32-byte session token.
// token must be the hex encoding of those 32 bytes.
func HashSessionToken(token string) (string, error) {
	raw, err := hex.DecodeString(token)
	if err != nil {
		return "", fmt.Errorf("auth: hash session token: %w", err)
	}
	if len(raw) != sessionTokenBytes {
		return "", fmt.Errorf("auth: hash session token: want %d bytes, got %d", sessionTokenBytes, len(raw))
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
