package sshmux

import (
	"errors"
	"net"
	"slices"
	"testing"
)

func denyDialer(string, string) (net.Conn, error) {
	return nil, errors.New("dial disabled in tests")
}

func TestChannelForwardMatching(t *testing.T) {
	for _, tc := range []struct {
		name    string
		names   []string
		host    string
		port    uint32
		allowed bool
	}{
		{"exact match", []string{"host.example.com:22"}, "host.example.com", 22, true},
		{"exact mismatch", []string{"host.example.com:22"}, "other.example.com", 22, false},
		{"port mismatch", []string{"host.example.com:22"}, "host.example.com", 2222, false},
		{"glob match", []string{"*.example.com:22"}, "host.example.com", 22, true},
		{"glob outside domain", []string{"*.example.com:22"}, "host.evil.com", 22, false},
		{"glob any port", []string{"host.example.com:*"}, "host.example.com", 2222, true},
		{"no remotes", nil, "host.example.com", 22, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{Dialer: denyDialer}

			var remotes []*Remote
			if tc.names != nil {
				remotes = []*Remote{{Names: tc.names, Address: "configured:22"}}
			}

			ch := newDirectTCPIP(tc.host, tc.port)
			s.ChannelForward(newTestSession(remotes), ch)

			var rejection string
			select {
			case rejection = <-ch.rejected:
			default:
			}

			denied := rejection == "remote host access denied for user"
			if denied == tc.allowed {
				t.Fatalf("allowed=%v but rejection was %q", tc.allowed, rejection)
			}
		})
	}
}

// Regression: a glob match rewrote the shared *Remote in place, prepending to
// Names and overwriting Address, which leaked between sessions.
func TestChannelForwardDoesNotMutateRemote(t *testing.T) {
	s := &Server{Dialer: denyDialer}
	remote := &Remote{
		Names:   []string{"*.example.com:22"},
		Address: "configured.example.com:22",
	}

	for range 3 {
		s.ChannelForward(
			newTestSession([]*Remote{remote}),
			newDirectTCPIP("host.example.com", 22))
	}

	if want := []string{"*.example.com:22"}; !slices.Equal(remote.Names, want) {
		t.Errorf("Names mutated: got %v, want %v", remote.Names, want)
	}

	if remote.Address != "configured.example.com:22" {
		t.Errorf("Address mutated: got %q", remote.Address)
	}
}

// The first matching remote wins, and later entries must not override it.
func TestChannelForwardFirstMatchWins(t *testing.T) {
	var selected string

	s := &Server{
		Dialer: denyDialer,
		Selected: func(_ *Session, addr string) error {
			selected = addr
			return errors.New("stop here")
		},
	}

	session := newTestSession([]*Remote{
		{Names: []string{"*.example.com:22"}, Address: "first:22"},
		{Names: []string{"host.example.com:22"}, Address: "second:22"},
	})

	s.ChannelForward(session, newDirectTCPIP("host.example.com", 22))

	if selected != "host.example.com:22" {
		t.Fatalf("expected the requested address, got %q", selected)
	}
}

func TestChannelForwardRejectsMalformedRequest(t *testing.T) {
	s := &Server{Dialer: denyDialer}
	ch := &malformedChannel{directTCPIP: *newDirectTCPIP("host", 22)}

	s.ChannelForward(newTestSession(nil), ch)

	select {
	case msg := <-ch.rejected:
		if msg != "malformed direct-tcpip request" {
			t.Fatalf("unexpected rejection %q", msg)
		}
	default:
		t.Fatal("malformed request was not rejected")
	}
}

type malformedChannel struct {
	directTCPIP
}

func (m *malformedChannel) ExtraData() []byte { return []byte{0x00, 0x01} }
