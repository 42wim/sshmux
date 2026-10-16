package sshmux

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// scriptedComm feeds input to the prompt helpers and records what they print.
type scriptedComm struct {
	in  io.Reader
	out bytes.Buffer
}

func newComm(input string) *scriptedComm {
	return &scriptedComm{in: strings.NewReader(input)}
}

func (c *scriptedComm) Read(p []byte) (int, error)  { return c.in.Read(p) }
func (c *scriptedComm) Write(p []byte) (int, error) { return c.out.Write(p) }

func testSession() *Session {
	return newTestSession([]*Remote{
		{Names: []string{"a:22"}, Description: "alpha", Address: "a:22"},
		{Names: []string{"b:22"}, Description: "bravo", Address: "b:22"},
	})
}

func TestStringCallback(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
		err   bool
	}{
		{"plain", "hunter2\r", "hunter2", false},
		{"backspace", "hunter22\x7f\r", "hunter2", false},
		{"backspace at start", "\x7fab\r", "ab", false},
		{"ctrl-c aborts", "abc\x03", "", true},
		{"eof", "abc", "", true},
		{"over the cap", strings.Repeat("x", maxInputLen+10) + "\r", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := StringCallback(newComm(tc.input), "pw:", true)

			if tc.err {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStringCallbackCapIsEnforced(t *testing.T) {
	_, err := StringCallback(newComm(strings.Repeat("x", maxInputLen+1)+"\r"), "pw:", true)
	if !errors.Is(err, errInputTooLong) {
		t.Fatalf("expected errInputTooLong, got %v", err)
	}
}

func TestStringCallbackHidesInput(t *testing.T) {
	comm := newComm("secret\r")

	if _, err := StringCallback(comm, "pw:", true); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(comm.out.String(), "secret") {
		t.Fatal("hidden input was echoed back")
	}
}

func TestDefaultInteractive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
		err   bool
	}{
		{"first", "0\r", "alpha", false},
		{"second", "1\r", "bravo", false},
		{"ctrl-c aborts", "\x03", "", true},
		{"eof", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DefaultInteractive(newComm(tc.input), testSession())

			if tc.err {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if got.Description != tc.want {
				t.Fatalf("got %q, want %q", got.Description, tc.want)
			}
		})
	}
}

func TestDefaultInteractiveRejectsBadSelection(t *testing.T) {
	// Out of range, then not a number, then a valid choice.
	comm := newComm("9\rxy\r1\r")

	got, err := DefaultInteractive(comm, testSession())
	if err != nil {
		t.Fatal(err)
	}

	if got.Description != "bravo" {
		t.Fatalf("got %q, want bravo", got.Description)
	}

	out := comm.out.String()
	if !strings.Contains(out, "No such server") {
		t.Error("expected an out-of-range message")
	}

	if !strings.Contains(out, "not a valid integer") {
		t.Error("expected a parse error message")
	}
}

func TestDefaultInteractiveNoRemotes(t *testing.T) {
	if _, err := DefaultInteractive(newComm("0\r"), newTestSession(nil)); err == nil {
		t.Fatal("expected an error when no remotes are permitted")
	}
}

func TestDefaultInteractiveCapsInput(t *testing.T) {
	// An over-long entry is discarded, then a valid choice is accepted.
	comm := newComm(strings.Repeat("9", maxInputLen+5) + "\r0\r")

	got, err := DefaultInteractive(comm, testSession())
	if err != nil {
		t.Fatal(err)
	}

	if got.Description != "alpha" {
		t.Fatalf("got %q, want alpha", got.Description)
	}

	if !strings.Contains(comm.out.String(), "input too long") {
		t.Error("expected an input-too-long message")
	}
}

func TestKeyboardChallenge(t *testing.T) {
	answers, err := KeyboardChallenge(
		newComm("alice\rhunter2\r"), "user", "login",
		[]string{"username:", "password:"}, []bool{true, false})
	if err != nil {
		t.Fatal(err)
	}

	if len(answers) != 2 || answers[0] != "alice" || answers[1] != "hunter2" {
		t.Fatalf("got %q", answers)
	}
}

func TestKeyboardChallengeCapsInput(t *testing.T) {
	_, err := KeyboardChallenge(
		newComm(strings.Repeat("x", maxInputLen+1)+"\r"), "user", "",
		[]string{"q:"}, []bool{false})

	if !errors.Is(err, errInputTooLong) {
		t.Fatalf("expected errInputTooLong, got %v", err)
	}
}

func TestKeyboardChallengeCtrlC(t *testing.T) {
	if _, err := KeyboardChallenge(
		newComm("\x03"), "user", "", []string{"q:"}, []bool{false}); err == nil {
		t.Fatal("expected an error on ctrl-c")
	}
}
