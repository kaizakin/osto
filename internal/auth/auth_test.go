package auth_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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
	validated, err := auth.ValidateSession(db, session.ID)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if validated == nil {
		t.Fatal("expected valid session for raw token")
	}
	if validated.ID != session.ID {
		t.Fatalf("ValidateSession.ID = %q, want raw token", validated.ID)
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

func TestHashSessionTokenIsSHA256OfRawBytes(t *testing.T) {
	token, err := auth.GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	got, err := auth.HashSessionToken(token)
	if err != nil {
		t.Fatalf("HashSessionToken: %v", err)
	}
	if got == token {
		t.Fatal("hash must not equal the raw token")
	}
	if len(got) != 64 {
		t.Fatalf("hash len = %d, want 64 hex chars", len(got))
	}
	again, err := auth.HashSessionToken(token)
	if err != nil || again != got {
		t.Fatalf("hash must be stable: %v %q vs %q", err, again, got)
	}
	raw, err := hex.DecodeString(token)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("HashSessionToken = %q, want sha256(raw) %q", got, want)
	}
}

func TestHashSessionTokenRejectsInvalidToken(t *testing.T) {
	if _, err := auth.HashSessionToken("not-hex"); err == nil {
		t.Fatal("expected error for non-hex token")
	}
	if _, err := auth.HashSessionToken("abcd"); err == nil {
		t.Fatal("expected error for token that is not 32 bytes")
	}
}

func TestSessionPlaintextNotStoredInDatabase(t *testing.T) {
	db := newTestDB(t)
	if err := auth.RegisterUser(db, "hashtest", "pass"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	user, err := auth.LoginUser(db, "hashtest", "pass")
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	session, err := auth.NewSession(db, user.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	wantHash, err := auth.HashSessionToken(session.ID)
	if err != nil {
		t.Fatalf("HashSessionToken: %v", err)
	}

	var storedID string
	if err := db.QueryRow(`SELECT id FROM sessions WHERE user_id = ?`, user.ID).Scan(&storedID); err != nil {
		t.Fatalf("select session id: %v", err)
	}
	if storedID == session.ID {
		t.Fatal("database stored the raw session token")
	}
	if storedID != wantHash {
		t.Fatalf("stored id = %q, want SHA-256 hex %q", storedID, wantHash)
	}

	plain, err := dbpkg.GetSession(db, session.ID)
	if err != nil {
		t.Fatalf("GetSession raw: %v", err)
	}
	if plain != nil {
		t.Fatal("looking up the raw token in the DB must miss")
	}
	hashed, err := dbpkg.GetSession(db, wantHash)
	if err != nil || hashed == nil {
		t.Fatalf("looking up the SHA-256 digest must hit: %v", err)
	}
}

func TestValidateSessionRejectsDigestUsedAsToken(t *testing.T) {
	db := newTestDB(t)
	if err := auth.RegisterUser(db, "digestuser", "pass"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	user, err := auth.LoginUser(db, "digestuser", "pass")
	if err != nil {
		t.Fatalf("LoginUser: %v", err)
	}
	session, err := auth.NewSession(db, user.ID, 15*time.Minute)
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	digest, err := auth.HashSessionToken(session.ID)
	if err != nil {
		t.Fatalf("HashSessionToken: %v", err)
	}
	validated, err := auth.ValidateSession(db, digest)
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if validated != nil {
		t.Fatal("the stored digest is not a usable session token")
	}
}

func TestValidateSessionRejectsMalformedToken(t *testing.T) {
	db := newTestDB(t)
	validated, err := auth.ValidateSession(db, "not-a-token")
	if err != nil {
		t.Fatalf("ValidateSession: %v", err)
	}
	if validated != nil {
		t.Fatal("expected nil for malformed token")
	}
}
