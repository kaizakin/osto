package cli

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/chzyer/readline"
	"github.com/kaizakin/osto/internal/auth"
	"github.com/kaizakin/osto/internal/models"
)

func TestPromptUnauthenticatedUsesOsto(t *testing.T) {
	if promptUnauthenticated != "osto> " {
		t.Fatalf("promptUnauthenticated = %q, want %q", promptUnauthenticated, "osto> ")
	}
}

func TestPromptAuthenticatedUsesOsto(t *testing.T) {
	got := promptAuthenticated("alice")
	want := "osto (alice)> "
	if got != want {
		t.Fatalf("promptAuthenticated = %q, want %q", got, want)
	}
}

func TestPromptPasswordUntilMinLengthRetriesUntilValid(t *testing.T) {
	inputs := [][]byte{[]byte("short"), []byte("1234567"), []byte("longenough")}
	var seen []string
	i := 0
	read := func(prompt string) ([]byte, error) {
		seen = append(seen, prompt)
		if i >= len(inputs) {
			t.Fatal("read more times than scripted inputs")
		}
		v := inputs[i]
		i++
		return v, nil
	}

	got, err := promptPasswordUntilMinLength(read, minPasswordLen)
	if err != nil {
		t.Fatalf("promptPasswordUntilMinLength: %v", err)
	}
	if !bytes.Equal(got, []byte("longenough")) {
		t.Fatalf("got %q, want longenough", got)
	}
	if i != 3 {
		t.Fatalf("reads = %d, want 3 (two retries then accept)", i)
	}
	for _, p := range seen {
		if p != "  Password: " {
			t.Fatalf("unexpected prompt %q", p)
		}
	}
	auth.ZeroBytes(got)
}

func TestPromptPasswordUntilMinLengthWipesRejected(t *testing.T) {
	short := []byte("shortpw")
	long := []byte("longenough")
	i := 0
	read := func(string) ([]byte, error) {
		if i == 0 {
			i++
			return short, nil
		}
		return long, nil
	}
	got, err := promptPasswordUntilMinLength(read, minPasswordLen)
	if err != nil {
		t.Fatalf("promptPasswordUntilMinLength: %v", err)
	}
	if !bytes.Equal(got, []byte("longenough")) {
		t.Fatalf("got %q", got)
	}
	for _, c := range short {
		if c != 0 {
			t.Fatal("rejected short password was not zeroed")
		}
	}
}

func TestPromptPasswordUntilMinLengthAcceptsExactMinimum(t *testing.T) {
	reads := 0
	read := func(string) ([]byte, error) {
		reads++
		return []byte("12345678"), nil
	}
	got, err := promptPasswordUntilMinLength(read, minPasswordLen)
	if err != nil {
		t.Fatalf("promptPasswordUntilMinLength: %v", err)
	}
	if !bytes.Equal(got, []byte("12345678")) {
		t.Fatalf("got %q", got)
	}
	if reads != 1 {
		t.Fatalf("reads = %d, want 1", reads)
	}
}

func TestPromptPasswordUntilMinLengthCancelDoesNotLoop(t *testing.T) {
	reads := 0
	read := func(string) ([]byte, error) {
		reads++
		return []byte("tiny"), io.EOF
	}
	_, err := promptPasswordUntilMinLength(read, minPasswordLen)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if reads != 1 {
		t.Fatalf("reads = %d, want 1 (cancel must not retry)", reads)
	}
}

func TestMinPasswordLen(t *testing.T) {
	if minPasswordLen != 8 {
		t.Fatalf("minPasswordLen = %d, want 8", minPasswordLen)
	}
}

func TestPromptLoginUntilSuccessRetriesWrongPassword(t *testing.T) {
	passwords := [][]byte{[]byte("wrong-one"), []byte("wrong-two"), []byte("correct-password")}
	i := 0
	read := func(prompt string) ([]byte, error) {
		if prompt != "  Password: " {
			t.Fatalf("prompt = %q", prompt)
		}
		if i >= len(passwords) {
			t.Fatal("read more times than scripted passwords")
		}
		v := passwords[i]
		i++
		return v, nil
	}
	attempts := 0
	user, err := promptLoginUntilSuccess("alice", read, func(username string, password []byte) (*models.User, error) {
		attempts++
		if username != "alice" {
			t.Fatalf("username = %q", username)
		}
		if !bytes.Equal(password, []byte("correct-password")) {
			return nil, errors.New("invalid username or password")
		}
		return &models.User{Username: username}, nil
	})
	if err != nil {
		t.Fatalf("promptLoginUntilSuccess: %v", err)
	}
	if user == nil || user.Username != "alice" {
		t.Fatalf("unexpected user: %+v", user)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	for _, p := range passwords {
		for _, c := range p {
			if c != 0 {
				t.Fatal("login password buffer was not zeroed")
			}
		}
	}
}

func TestPromptLoginUntilSuccessCancelOnCtrlC(t *testing.T) {
	reads := 0
	read := func(string) ([]byte, error) {
		reads++
		if reads == 1 {
			return []byte("wrong"), nil
		}
		return nil, readline.ErrInterrupt
	}
	attempts := 0
	user, err := promptLoginUntilSuccess("bob", read, func(string, []byte) (*models.User, error) {
		attempts++
		return nil, errors.New("invalid username or password")
	})
	if !errors.Is(err, readline.ErrInterrupt) {
		t.Fatalf("err = %v, want readline.ErrInterrupt", err)
	}
	if user != nil {
		t.Fatal("expected nil user after cancel")
	}
	if reads != 2 {
		t.Fatalf("reads = %d, want 2 (one failed login then Ctrl-C)", reads)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestPromptLoginUntilSuccessCancelOnEOF(t *testing.T) {
	reads := 0
	_, err := promptLoginUntilSuccess("bob", func(string) ([]byte, error) {
		reads++
		return nil, io.EOF
	}, func(string, []byte) (*models.User, error) {
		t.Fatal("login must not run after EOF")
		return nil, nil
	})
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want io.EOF", err)
	}
	if reads != 1 {
		t.Fatalf("reads = %d, want 1", reads)
	}
}
