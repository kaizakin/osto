package cli

import (
	"errors"
	"io"
	"testing"
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
	inputs := []string{"short", "1234567", "longenough"}
	var seen []string
	i := 0
	read := func(prompt string) (string, error) {
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
	if got != "longenough" {
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
}

func TestPromptPasswordUntilMinLengthAcceptsExactMinimum(t *testing.T) {
	reads := 0
	read := func(string) (string, error) {
		reads++
		return "12345678", nil
	}
	got, err := promptPasswordUntilMinLength(read, minPasswordLen)
	if err != nil {
		t.Fatalf("promptPasswordUntilMinLength: %v", err)
	}
	if got != "12345678" {
		t.Fatalf("got %q", got)
	}
	if reads != 1 {
		t.Fatalf("reads = %d, want 1", reads)
	}
}

func TestPromptPasswordUntilMinLengthCancelDoesNotLoop(t *testing.T) {
	reads := 0
	read := func(string) (string, error) {
		reads++
		return "tiny", io.EOF
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

