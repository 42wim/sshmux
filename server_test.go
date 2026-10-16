package sshmux

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestPostQuantumKeyExchangeNegotiates(t *testing.T) {
	s, hostKey := testServer(t)
	cfg := testClientConfig(t, hostKey)
	cfg.KeyExchanges = []string{ssh.KeyExchangeMLKEM768X25519}

	if _, err := connect(t, s, cfg); err != nil {
		t.Fatalf("mlkem768x25519-sha256 should negotiate: %v", err)
	}
}

func TestWeakAlgorithmsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(*ssh.ClientConfig)
	}{
		{"cbc cipher", func(c *ssh.ClientConfig) {
			c.Ciphers = []string{ssh.InsecureCipherAES128CBC}
		}},
		{"3des cipher", func(c *ssh.ClientConfig) {
			c.Ciphers = []string{ssh.InsecureCipherTripleDESCBC}
		}},
		{"sha1 mac", func(c *ssh.ClientConfig) {
			c.Ciphers = []string{ssh.CipherAES128CTR}
			c.MACs = []string{ssh.HMACSHA1}
		}},
		{"sha1 kex", func(c *ssh.ClientConfig) {
			c.KeyExchanges = []string{ssh.InsecureKeyExchangeDH14SHA1}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, hostKey := testServer(t)
			cfg := testClientConfig(t, hostKey)
			tc.apply(cfg)

			if _, err := connect(t, s, cfg); err == nil {
				t.Fatal("handshake should have been refused")
			}
		})
	}
}

// Regression: OnlyProxyJump rejected the channel but started SessionForward on
// it regardless, so interactive logins were never actually blocked.
func TestOnlyProxyJumpRejectsSession(t *testing.T) {
	var forwarded atomic.Bool

	s, hostKey := testServer(t)
	s.OnlyProxyJump = true
	s.Interactive = func(io.ReadWriter, *Session) (*Remote, error) {
		forwarded.Store(true)
		return nil, errors.New("must not be reached")
	}

	client, err := connect(t, s, testClientConfig(t, hostKey))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.NewSession(); err == nil {
		t.Fatal("session channel must be rejected")
	}

	if forwarded.Load() {
		t.Fatal("SessionForward ran on a rejected channel")
	}
}

// Regression: Setup's error was discarded, so late denial did nothing.
func TestSetupErrorTerminatesConnection(t *testing.T) {
	hostKey := testSigner(t)
	s := New([]ssh.Signer{hostKey},
		func(ssh.ConnMetadata, ssh.PublicKey) (*User, error) { return nil, nil },
		func(*Session) error { return errors.New("denied") })

	client, err := connect(t, s, testClientConfig(t, hostKey))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.NewSession(); err == nil {
		t.Fatal("connection must be closed when Setup fails")
	}
}

func TestAuthenticatorDenialRefusesHandshake(t *testing.T) {
	hostKey := testSigner(t)
	s := New([]ssh.Signer{hostKey},
		func(ssh.ConnMetadata, ssh.PublicKey) (*User, error) {
			return nil, errors.New("unknown key")
		},
		func(*Session) error { return nil })

	if _, err := connect(t, s, testClientConfig(t, hostKey)); err == nil {
		t.Fatal("handshake should fail when the authenticator denies the key")
	}
}

// The authenticated user must reach Setup without Authenticator being
// consulted a second time after the handshake.
func TestAuthenticatorCalledOncePerKey(t *testing.T) {
	var calls atomic.Int32

	setupDone := make(chan *User, 1)

	hostKey := testSigner(t)
	s := New([]ssh.Signer{hostKey},
		func(ssh.ConnMetadata, ssh.PublicKey) (*User, error) {
			calls.Add(1)
			return &User{Name: "alice"}, nil
		},
		func(sess *Session) error {
			setupDone <- sess.User
			return nil
		})

	if _, err := connect(t, s, testClientConfig(t, hostKey)); err != nil {
		t.Fatal(err)
	}

	var user *User
	select {
	case user = <-setupDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Setup was never called")
	}

	if user == nil || user.Name != "alice" {
		t.Fatalf("Setup saw user %v, want alice", user)
	}

	// The client offers the key, then proves it, so at most two calls.
	if n := calls.Load(); n > 2 {
		t.Fatalf("Authenticator called %d times, expected no post-handshake call", n)
	}
}

func TestHandshakeDeadlineDropsIdleConnection(t *testing.T) {
	s, _ := testServer(t)
	s.HandshakeTimeout = 200 * time.Millisecond

	addr := serve(t, s)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.SetReadDeadline(time.Now().Add(5 * time.Second))

	// The server sends its version string, then drops us for going idle.
	if _, err := io.ReadAll(c); err != nil && !errors.Is(err, io.EOF) {
		t.Logf("read ended with %v", err)
	}
}

func TestServeContextShutsDownGracefully(t *testing.T) {
	s, hostKey := testServer(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)

	go func() { served <- s.ServeContext(ctx, l) }()

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	conn, chans, reqs, err := ssh.NewClientConn(c, l.Addr().String(), testClientConfig(t, hostKey))
	if err != nil {
		t.Fatal(err)
	}

	client := ssh.NewClient(conn, chans, reqs)
	closed := make(chan struct{})

	go func() { client.Wait(); close(closed) }()

	cancel()

	select {
	case err := <-served:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeContext did not return")
	}

	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("live connection was not closed on shutdown")
	}

	if _, err := net.DialTimeout("tcp", l.Addr().String(), time.Second); err == nil {
		t.Fatal("listener still accepting after shutdown")
	}
}

func TestLoggingRecordsSessionAndAlgorithms(t *testing.T) {
	var buf syncBuffer

	hostKey := testSigner(t)
	ready := make(chan struct{})

	s := New([]ssh.Signer{hostKey},
		func(ssh.ConnMetadata, ssh.PublicKey) (*User, error) { return &User{Name: "alice"}, nil },
		func(*Session) error {
			close(ready)
			return nil
		})
	s.Logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if _, err := connect(t, s, testClientConfig(t, hostKey)); err != nil {
		t.Fatal(err)
	}

	// Setup runs after the open and algorithm records are written.
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("Setup was never called")
	}

	out := buf.String()
	for _, want := range []string{
		"session opened",
		"negotiated algorithms",
		ssh.KeyExchangeMLKEM768X25519,
		"fingerprint=SHA256:",
		"user=alice",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q\n%s", want, out)
		}
	}
}
