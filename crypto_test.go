package sshmux

import (
	"net"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestDefaultsAreSupportedAndSecure(t *testing.T) {
	supported, insecure := ssh.SupportedAlgorithms(), ssh.InsecureAlgorithms()

	for _, tc := range []struct {
		name      string
		got       []string
		supported []string
		insecure  []string
	}{
		{"KeyExchanges", DefaultKeyExchanges, supported.KeyExchanges, insecure.KeyExchanges},
		{"Ciphers", DefaultCiphers, supported.Ciphers, insecure.Ciphers},
		{"MACs", DefaultMACs, supported.MACs, insecure.MACs},
		{"HostKeyAlgorithms", DefaultHostKeyAlgorithms, supported.HostKeys, insecure.HostKeys},
		{"PublicKeyAuthAlgorithms", DefaultPublicKeyAuthAlgorithms, supported.PublicKeyAuths, insecure.PublicKeyAuths},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.got) == 0 {
				t.Fatal("list is empty")
			}

			for _, alg := range tc.got {
				if slices.Contains(tc.insecure, alg) {
					t.Errorf("%q is listed as insecure by x/crypto", alg)
				}

				if !slices.Contains(tc.supported, alg) {
					t.Errorf("%q is not supported by x/crypto", alg)
				}
			}
		})
	}
}

func TestPostQuantumKeyExchangePreferred(t *testing.T) {
	if DefaultKeyExchanges[0] != ssh.KeyExchangeMLKEM768X25519 {
		t.Fatalf("expected %q first, got %q",
			ssh.KeyExchangeMLKEM768X25519, DefaultKeyExchanges[0])
	}
}

func TestOnlyAEADCiphersOffered(t *testing.T) {
	aead := []string{ssh.CipherAES128GCM, ssh.CipherAES256GCM, ssh.CipherChaCha20Poly1305}

	for _, c := range DefaultCiphers {
		if !slices.Contains(aead, c) {
			t.Errorf("non-AEAD cipher %q offered", c)
		}
	}
}

func TestSHA1AlgorithmsNotOffered(t *testing.T) {
	banned := []string{
		ssh.HMACSHA1, ssh.InsecureHMACSHA196,
		ssh.KeyAlgoRSA, ssh.InsecureKeyAlgoDSA,
		ssh.InsecureKeyExchangeDH1SHA1, ssh.InsecureKeyExchangeDH14SHA1,
	}

	all := slices.Concat(DefaultKeyExchanges, DefaultCiphers, DefaultMACs,
		DefaultHostKeyAlgorithms, DefaultPublicKeyAuthAlgorithms)

	for _, alg := range all {
		if slices.Contains(banned, alg) {
			t.Errorf("SHA-1 era algorithm %q offered", alg)
		}
	}
}

func TestCryptoConfigOverrides(t *testing.T) {
	s := &Server{Ciphers: []string{ssh.CipherAES256GCM}}

	if got := s.cryptoConfig().Ciphers; len(got) != 1 || got[0] != ssh.CipherAES256GCM {
		t.Fatalf("override ignored, got %v", got)
	}

	if got := s.cryptoConfig().MACs; !slices.Equal(got, DefaultMACs) {
		t.Fatalf("unset field should fall back to defaults, got %v", got)
	}
}

func TestUpstreamHostKeyCallbackDefaultsToInsecure(t *testing.T) {
	s := &Server{}
	if s.upstreamHostKeyCallback() == nil {
		t.Fatal("expected a non-nil fallback callback")
	}

	called := false
	s.UpstreamHostKeyCallback = func(string, net.Addr, ssh.PublicKey) error {
		called = true
		return nil
	}

	if err := s.upstreamHostKeyCallback()("h", nil, nil); err != nil {
		t.Fatal(err)
	}

	if !called {
		t.Fatal("configured callback was not used")
	}
}
