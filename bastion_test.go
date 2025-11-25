package main

import (
	"os"
	"path/filepath"
	"testing"
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
