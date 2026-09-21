package auth_test

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kaizakin/osto/internal/auth"
	dbpkg "github.com/kaizakin/osto/internal/db"
	"github.com/pquerna/otp/totp"
	_ "modernc.org/sqlite"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := dbpkg.Open(
		filepath.Join(t.TempDir(), "test.db"),
		findSchemaPath(t),
	)
	if err != nil {
		t.Fatalf("newTestDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func findSchemaPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "db", "schema.sql")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("findSchemaPath: could not locate db/schema.sql")
		}
		dir = parent
	}
}

func TestHashPassword(t *testing.T) {
	hash, err := auth.HashPassword("supersecret123!")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == "" || hash == "supersecret123!" {
		t.Fatal("unexpected hash value")
	}
}

func TestCheckPasswordCorrect(t *testing.T) {
	hash, _ := auth.HashPassword("correct-horse-battery-staple")
	if !auth.CheckPassword(hash, "correct-horse-battery-staple") {
		t.Error("CheckPassword returned false for correct password")
	}
}

func TestCheckPasswordIncorrect(t *testing.T) {
	hash, _ := auth.HashPassword("correct-password")
	if auth.CheckPassword(hash, "wrong-password") {
		t.Error("CheckPassword returned true for wrong password")
	}
}

func TestHashesAreDifferent(t *testing.T) {
	h1, _ := auth.HashPassword("same-password")
	h2, _ := auth.HashPassword("same-password")
	if h1 == h2 {
		t.Error("expected different hashes (unique salts)")
	}
}

func TestLoginLockoutAfterThreeFailures(t *testing.T) {
	db := newTestDB(t)
	if err := auth.RegisterUser(db, "lockeduser", "correct-password"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	for i := 1; i <= 3; i++ {
		if _, err := auth.LoginUser(db, "lockeduser", "wrong"); err == nil {
			t.Fatalf("attempt %d: expected error", i)
		}
	}
	_, err := auth.LoginUser(db, "lockeduser", "wrong")
	if !errors.Is(err, auth.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got: %v", err)
	}
}

func TestSuccessfulLoginResetsFailedAttempts(t *testing.T) {
	db := newTestDB(t)
	if err := auth.RegisterUser(db, "resetuser", "mypassword"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	for i := 0; i < 2; i++ {
		_, _ = auth.LoginUser(db, "resetuser", "bad")
	}
	user, err := auth.LoginUser(db, "resetuser", "mypassword")
	if err != nil || user == nil {
		t.Fatalf("LoginUser: %v", err)
	}
}

func TestLockedAccountRejectsCorrectPassword(t *testing.T) {
	db := newTestDB(t)
	if err := auth.RegisterUser(db, "alwayslocked", "correct"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	for i := 0; i < 3; i++ {
		_, _ = auth.LoginUser(db, "alwayslocked", "bad")
	}
	_, err := auth.LoginUser(db, "alwayslocked", "correct")
	if !errors.Is(err, auth.ErrAccountLocked) {
		t.Fatalf("expected ErrAccountLocked, got: %v", err)
	}
}

func TestNewSessionIsValid(t *testing.T) {
	db := newTestDB(t)
	if err := auth.RegisterUser(db, "sessionuser", "pass"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	user, err := auth.LoginUser(db, "sessionuser", "pass")
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	session, err := auth.NewSession(db, user.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if session.IsExpired() {
		t.Error("fresh session should not be expired")
	}
}

func TestValidateSessionExpired(t *testing.T) {
	db := newTestDB(t)
	if err := auth.RegisterUser(db, "expireduser", "pass"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	user, err := auth.LoginUser(db, "expireduser", "pass")
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	session, err := auth.NewSession(db, user.ID, -1*time.Second)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	time.Sleep(10 * time.Millisecond)
	validated, err := auth.ValidateSession(db, session.ID)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if validated != nil {
		t.Error("expected nil for expired session")
	}
}

func TestDestroySession(t *testing.T) {
	db := newTestDB(t)
	if err := auth.RegisterUser(db, "destroyuser", "pass"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	user, err := auth.LoginUser(db, "destroyuser", "pass")
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	session, err := auth.NewSession(db, user.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := auth.DestroySession(db, session.ID); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
	validated, err := auth.ValidateSession(db, session.ID)
	if err != nil {
		t.Fatalf("ValidateSession after destroy: %v", err)
	}
	if validated != nil {
		t.Error("expected nil session after destruction")
	}
}

func TestGenerateTOTPSecret(t *testing.T) {
	key, err := auth.GenerateTOTPSecret("testuser")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if key.Secret() == "" || key.URL() == "" {
		t.Error("expected non-empty secret and URL")
	}
	if key.Issuer() != "osto" {
		t.Errorf("issuer = %q, want osto", key.Issuer())
	}
}

func TestValidateTOTPCodeSuccess(t *testing.T) {
	key, err := auth.GenerateTOTPSecret("testuser")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	if !auth.ValidateTOTPCode(key.Secret(), code) {
		t.Error("ValidateTOTPCode returned false for valid code")
	}
}

func TestValidateTOTPCodeInvalid(t *testing.T) {
	key, err := auth.GenerateTOTPSecret("testuser")
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if auth.ValidateTOTPCode(key.Secret(), "000000") {
		t.Error("ValidateTOTPCode returned true for all-zero code")
	}
}

func TestGenerateSessionIDUniqueness(t *testing.T) {
	id1, err := auth.GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	id2, err := auth.GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	if id1 == id2 {
		t.Error("expected unique session IDs")
	}
	if len(id1) != 64 {
		t.Errorf("expected 64-char hex ID, got len=%d", len(id1))
	}
}
