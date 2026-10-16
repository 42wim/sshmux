package sshmux

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	return signer
}

// testServer returns a server that admits every key and permits no remotes,
// along with its host key.
func testServer(t *testing.T) (*Server, ssh.Signer) {
	t.Helper()

	hostKey := testSigner(t)
	s := New([]ssh.Signer{hostKey},
		func(ssh.ConnMetadata, ssh.PublicKey) (*User, error) { return &User{Name: "test"}, nil },
		func(*Session) error { return nil })

	return s, hostKey
}

func testClientConfig(t *testing.T, hostKey ssh.Signer) *ssh.ClientConfig {
	t.Helper()

	return &ssh.ClientConfig{
		User:            "user",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(testSigner(t))},
		HostKeyCallback: ssh.FixedHostKey(hostKey.PublicKey()),
	}
}

// serve runs s on a loopback listener and returns its address. net.Pipe cannot
// be used here: it is unbuffered and deadlocks the SSH handshake.
func serve(t *testing.T, s *Server) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}

			go s.HandleConn(c)
		}
	}()

	return l.Addr().String()
}

// connect performs a full handshake against s and returns the client.
func connect(t *testing.T, s *Server, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	t.Helper()

	addr := serve(t, s)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}

	conn, chans, reqs, err := ssh.NewClientConn(c, addr, cfg)
	if err != nil {
		c.Close()
		return nil, err
	}

	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { client.Close() })

	return client, nil
}

// directTCPIP builds a direct-tcpip channel open request for the given target.
type directTCPIP struct {
	host string
	port uint32

	rejected chan string
}

func newDirectTCPIP(host string, port uint32) *directTCPIP {
	return &directTCPIP{host: host, port: port, rejected: make(chan string, 1)}
}

func (d *directTCPIP) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, io.EOF
}

func (d *directTCPIP) Reject(_ ssh.RejectionReason, message string) error {
	select {
	case d.rejected <- message:
	default:
	}

	return nil
}

func (d *directTCPIP) ChannelType() string { return "direct-tcpip" }

func (d *directTCPIP) ExtraData() []byte {
	return ssh.Marshal(channelOpenDirectMsg{RAddr: d.host, RPort: d.port})
}

// fakeConn is the minimum ssh.Conn needed to build a *ssh.ServerConn for tests
// that exercise forwarding without a real handshake.
type fakeConn struct{ ssh.Conn }

func (fakeConn) User() string         { return "tester" }
func (fakeConn) RemoteAddr() net.Addr { return fakeAddr{} }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "198.51.100.1:2222" }

// testSession builds a Session with just enough of a connection to log against.
func newTestSession(remotes []*Remote) *Session {
	return &Session{
		Conn:    &ssh.ServerConn{Conn: fakeConn{}},
		Remotes: remotes,
	}
}

// syncBuffer collects log output written from handler goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}
