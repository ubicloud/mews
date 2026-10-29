package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestGetAgentSocket(t *testing.T) {
	// Save original state
	originalAuthSock := os.Getenv("SSH_AUTH_SOCK")
	originalAgentSocket := agentSocket
	defer func() {
		if originalAuthSock != "" {
			os.Setenv("SSH_AUTH_SOCK", originalAuthSock)
		} else {
			os.Unsetenv("SSH_AUTH_SOCK")
		}
		agentSocket = originalAgentSocket
	}()

	tests := []struct {
		name         string
		hostname     string
		agentFlag    string
		authSock     string
		wantContains string
		wantEmpty    bool
		description  string
	}{
		{
			name:         "fallback to SSH_AUTH_SOCK when ssh -G fails",
			hostname:     "nonexistent-host-that-will-fail-ssh-g-12345",
			agentFlag:    "",
			authSock:     "/tmp/test-agent.sock",
			wantContains: "/tmp/test-agent.sock",
			description:  "When ssh -G fails and no -agent flag, should fall back to SSH_AUTH_SOCK",
		},
		{
			name:        "empty when SSH_AUTH_SOCK not set and ssh -G fails",
			hostname:    "nonexistent-host-that-will-fail-ssh-g-12345",
			agentFlag:   "",
			authSock:    "",
			wantEmpty:   true,
			description: "When both ssh -G fails and SSH_AUTH_SOCK is empty, should return empty",
		},
		{
			name:         "-agent flag takes precedence over SSH_AUTH_SOCK",
			hostname:     "localhost",
			agentFlag:    "/tmp/flag-agent.sock",
			authSock:     "/tmp/env-agent.sock",
			wantContains: "/tmp/flag-agent.sock",
			description:  "-agent flag should override SSH_AUTH_SOCK",
		},
		{
			name:         "-agent flag takes precedence over ssh -G",
			hostname:     "localhost",
			agentFlag:    "/tmp/flag-agent.sock",
			authSock:     "/tmp/env-agent.sock",
			wantContains: "/tmp/flag-agent.sock",
			description:  "-agent flag should override .ssh/config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up state
			agentSocket = tt.agentFlag
			if tt.authSock != "" {
				os.Setenv("SSH_AUTH_SOCK", tt.authSock)
			} else {
				os.Unsetenv("SSH_AUTH_SOCK")
			}

			got, err := getAgentSocket(tt.hostname)
			if err != nil {
				t.Fatalf("getAgentSocket() error = %v", err)
			}

			if tt.wantEmpty {
				if got != "" {
					t.Errorf("getAgentSocket() = %q, want empty string", got)
				}
				return
			}

			if tt.wantContains != "" {
				if got != tt.wantContains {
					t.Errorf("getAgentSocket() = %q, want %q", got, tt.wantContains)
				}
			}

			t.Logf("getAgentSocket(%q) = %q (%s)", tt.hostname, got, tt.description)
		})
	}
}

func TestGetIdentityAgentFromSSHConfig(t *testing.T) {
	tests := []struct {
		name        string
		hostname    string
		wantErr     bool
		description string
	}{
		{
			name:        "localhost should succeed",
			hostname:    "localhost",
			wantErr:     false,
			description: "ssh -G localhost should work on any system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getIdentityAgentFromSSHConfig(tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("getIdentityAgentFromSSHConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				t.Logf("getIdentityAgentFromSSHConfig(%q) = %q (%s)", tt.hostname, got, tt.description)
			}
		})
	}
}

func TestAgentSocketPrecedence(t *testing.T) {
	// Save original state
	originalAuthSock := os.Getenv("SSH_AUTH_SOCK")
	originalAgentSocket := agentSocket
	defer func() {
		if originalAuthSock != "" {
			os.Setenv("SSH_AUTH_SOCK", originalAuthSock)
		} else {
			os.Unsetenv("SSH_AUTH_SOCK")
		}
		agentSocket = originalAgentSocket
	}()

	// Create a temporary .ssh/config for testing
	homeDir, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("Failed to get home directory: %v", err)
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	configPath := filepath.Join(sshDir, "config")

	// Check if .ssh/config exists and back it up
	var originalConfig []byte
	var configExists bool
	if data, err := os.ReadFile(configPath); err == nil {
		originalConfig = data
		configExists = true
	}

	// Restore original config after test
	defer func() {
		if configExists {
			os.WriteFile(configPath, originalConfig, 0600)
		}
	}()

	// Test tilde expansion (ssh -G does this for us)
	t.Run("tilde expansion", func(t *testing.T) {
		agentSocket = ""
		testConfig := `Host test-tilde-host
    IdentityAgent ~/.test-agent.sock
`
		os.MkdirAll(sshDir, 0700)
		if err := os.WriteFile(configPath, []byte(testConfig), 0600); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		got, err := getAgentSocket("test-tilde-host")
		if err != nil {
			t.Fatalf("getAgentSocket() error = %v", err)
		}

		// ssh -G expands ~ to the actual home directory
		expected := filepath.Join(homeDir, ".test-agent.sock")
		if got != expected {
			t.Errorf("getAgentSocket() = %q, want %q (ssh -G should expand ~)", got, expected)
		}
	})

	// Test that ssh -G does NOT expand environment variables
	t.Run("environment variable not expanded by ssh -G", func(t *testing.T) {
		agentSocket = ""
		os.Setenv("MY_CUSTOM_AGENT", "/tmp/my-custom-agent.sock")
		defer os.Unsetenv("MY_CUSTOM_AGENT")

		testConfig := `Host test-env-host
    IdentityAgent $MY_CUSTOM_AGENT
`
		if err := os.WriteFile(configPath, []byte(testConfig), 0600); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		got, err := getAgentSocket("test-env-host")
		if err != nil {
			t.Fatalf("getAgentSocket() error = %v", err)
		}

		// ssh -G does NOT expand environment variables, so we get the literal string
		if got != "$MY_CUSTOM_AGENT" {
			t.Errorf("getAgentSocket() = %q, want %q (ssh -G does not expand env vars)", got, "$MY_CUSTOM_AGENT")
		}
	})

	// Test SSH_AUTH_SOCK special value
	t.Run("SSH_AUTH_SOCK special value", func(t *testing.T) {
		agentSocket = ""
		os.Setenv("SSH_AUTH_SOCK", "/tmp/env-agent.sock")

		testConfig := `Host test-ssh-auth-sock-host
    IdentityAgent SSH_AUTH_SOCK
`
		if err := os.WriteFile(configPath, []byte(testConfig), 0600); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		got, err := getAgentSocket("test-ssh-auth-sock-host")
		if err != nil {
			t.Fatalf("getAgentSocket() error = %v", err)
		}

		if got != "/tmp/env-agent.sock" {
			t.Errorf("getAgentSocket() = %q, want %q", got, "/tmp/env-agent.sock")
		}
	})

	// Test absolute path
	t.Run("absolute path", func(t *testing.T) {
		agentSocket = ""
		testConfig := `Host test-absolute-host
    IdentityAgent /var/run/custom-agent.sock
`
		if err := os.WriteFile(configPath, []byte(testConfig), 0600); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		got, err := getAgentSocket("test-absolute-host")
		if err != nil {
			t.Fatalf("getAgentSocket() error = %v", err)
		}

		if got != "/var/run/custom-agent.sock" {
			t.Errorf("getAgentSocket() = %q, want %q", got, "/var/run/custom-agent.sock")
		}
	})

	// Test "none" value falls back to SSH_AUTH_SOCK
	t.Run("none value fallback", func(t *testing.T) {
		agentSocket = ""
		os.Setenv("SSH_AUTH_SOCK", "/tmp/fallback-agent.sock")

		testConfig := `Host test-none-host
    IdentityAgent none
`
		if err := os.WriteFile(configPath, []byte(testConfig), 0600); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		got, err := getAgentSocket("test-none-host")
		if err != nil {
			t.Fatalf("getAgentSocket() error = %v", err)
		}

		if got != "/tmp/fallback-agent.sock" {
			t.Errorf("getAgentSocket() = %q, want %q (should fall back to SSH_AUTH_SOCK)", got, "/tmp/fallback-agent.sock")
		}
	})

	// Test -agent flag overrides .ssh/config
	t.Run("-agent flag overrides .ssh/config", func(t *testing.T) {
		agentSocket = "/tmp/flag-override.sock"
		testConfig := `Host test-override-host
    IdentityAgent /var/run/config-agent.sock
`
		if err := os.WriteFile(configPath, []byte(testConfig), 0600); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		got, err := getAgentSocket("test-override-host")
		if err != nil {
			t.Fatalf("getAgentSocket() error = %v", err)
		}

		if got != "/tmp/flag-override.sock" {
			t.Errorf("getAgentSocket() = %q, want %q (-agent flag should override .ssh/config)", got, "/tmp/flag-override.sock")
		}
	})
}

// failingAgent is an agent whose key at index bad cannot sign, as when the
// key is on a device that is not plugged in. It counts each key's signing.
type failingAgent struct {
	agent.ExtendedAgent
	bad   ssh.PublicKey
	mu    sync.Mutex
	signs map[string]int
}

func (a *failingAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *failingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	a.signs[ssh.FingerprintSHA256(key)]++
	a.mu.Unlock()
	if bytes.Equal(key.Marshal(), a.bad.Marshal()) {
		return nil, errors.New("device not found")
	}
	return a.ExtendedAgent.SignWithFlags(key, data, flags)
}

// TestConnectToBastionSkipsKeyAgentCannotSign runs connectToBastion against
// an agent holding two keys, the first of which cannot sign, and a server
// that accepts the keys in accepted.
func TestConnectToBastionSkipsKeyAgentCannotSign(t *testing.T) {
	for _, tc := range []struct {
		name     string
		accepted []int
	}{
		{"server accepts both keys", []int{0, 1}},
		{"server accepts only the second key", []int{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyring := agent.NewKeyring().(agent.ExtendedAgent)
			var pubs []ssh.PublicKey
			for i := 0; i < 2; i++ {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				if err := keyring.Add(agent.AddedKey{PrivateKey: priv, Comment: fmt.Sprintf("key%d", i)}); err != nil {
					t.Fatal(err)
				}
				signer, err := ssh.NewSignerFromKey(priv)
				if err != nil {
					t.Fatal(err)
				}
				pubs = append(pubs, signer.PublicKey())
			}
			fa := &failingAgent{ExtendedAgent: keyring, bad: pubs[0], signs: map[string]int{}}

			sock := filepath.Join(t.TempDir(), "agent.sock")
			agentListener, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer agentListener.Close()
			go func() {
				for {
					c, err := agentListener.Accept()
					if err != nil {
						return
					}
					go func() {
						defer c.Close()
						agent.ServeAgent(fa, c)
					}()
				}
			}()
			originalAgentSocket := agentSocket
			agentSocket = sock
			defer func() { agentSocket = originalAgentSocket }()

			_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			hostKey, err := ssh.NewSignerFromKey(hostPriv)
			if err != nil {
				t.Fatal(err)
			}
			config := &ssh.ServerConfig{
				PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					for _, i := range tc.accepted {
						if bytes.Equal(key.Marshal(), pubs[i].Marshal()) {
							return nil, nil
						}
					}
					return nil, errors.New("key not authorized")
				},
			}
			config.AddHostKey(hostKey)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				for {
					c, err := listener.Accept()
					if err != nil {
						return
					}
					go func() {
						sshConn, chans, reqs, err := ssh.NewServerConn(c, config)
						if err != nil {
							c.Close()
							return
						}
						defer sshConn.Close()
						go ssh.DiscardRequests(reqs)
						for ch := range chans {
							ch.Reject(ssh.Prohibited, "test server")
						}
					}()
				}
			}()

			bastion := &Bastion{
				Name:        "test-bastion",
				Host:        "127.0.0.1",
				Port:        fmt.Sprint(listener.Addr().(*net.TCPAddr).Port),
				User:        "tunnel",
				Fingerprint: ssh.FingerprintSHA256(hostKey.PublicKey()),
			}
			client, err := connectToBastion(bastion)
			if err != nil {
				t.Fatalf("connectToBastion: %v", err)
			}
			client.Close()

			fa.mu.Lock()
			defer fa.mu.Unlock()
			// x/crypto asks the server about each key before signing with
			// it, so a key the server does not accept is never signed with.
			wantBad := 0
			if len(tc.accepted) == 2 {
				wantBad = 1
			}
			if got := fa.signs[ssh.FingerprintSHA256(pubs[0])]; got != wantBad {
				t.Errorf("agent asked to sign with the first key %d times, want %d", got, wantBad)
			}
			if got := fa.signs[ssh.FingerprintSHA256(pubs[1])]; got != 1 {
				t.Errorf("agent asked to sign with the second key %d times, want 1", got)
			}
		})
	}
}

func TestDescribeKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	want := "ssh-ed25519 " + ssh.FingerprintSHA256(pub)
	if got := describeKey(pub); got != want {
		t.Errorf("describeKey = %q, want %q", got, want)
	}
	key := &agent.Key{Format: pub.Type(), Blob: pub.Marshal(), Comment: "yubikey-a"}
	if got := describeKey(key); got != want+" (yubikey-a)" {
		t.Errorf("describeKey = %q, want %q", got, want+" (yubikey-a)")
	}
}
