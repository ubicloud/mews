package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// identityAgentRegex matches the identityagent line from ssh -G output
var identityAgentRegex = regexp.MustCompile(`(?m)^identityagent\s+(.*)$`)

// Connection manages a single SSH connection to a bastion set
type Connection struct {
	setName      string
	bastions     []Bastion
	client       *ssh.Client
	currentIndex int
	mu           sync.RWMutex
	reconnecting bool
	stopCh       chan struct{}
	readyCh      chan struct{}

	// lost is set when the link under client breaks. readyCh is closed
	// while client is set, and Connect makes a new one when it discards
	// client.
	lost *atomic.Bool

	// Muxer state (see muxer.go). When the active bastion has muxer: true,
	// bc.sshMuxer caches one sshMuxer -- an SSH session whose stdio carries a
	// stream-multiplexing protocol -- so all upstream dials share one session
	// instead of opening a channel each. muxerMu guards the field; only
	// getOrCreateMuxer/dropMuxer touch it. nil when no muxer has started.
	muxerMu  sync.Mutex
	sshMuxer *sshMuxer
}

func NewConnection(setName string, bastions []Bastion) *Connection {
	return &Connection{
		setName:      setName,
		bastions:     bastions,
		currentIndex: 0,
		stopCh:       make(chan struct{}),
		readyCh:      make(chan struct{}),
	}
}

// Connect starts connecting the set in the background, unless it is
// already connected or an attempt is in progress. A lost client is closed
// first.
func (bc *Connection) Connect() {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.reconnecting || bc.live() != nil {
		return
	}
	bc.reconnecting = true
	if bc.client != nil {
		bc.client.Close()
		bc.client = nil
		bc.readyCh = make(chan struct{})
	}
	go bc.reconnect()
}

// link is the TCP connection to a bastion. A read or write error sets lost
// before x/crypto fails the channels on the link. Close also sets lost,
// because x/crypto calls Close when the SSH transport ends for other reasons.
type link struct {
	net.Conn
	lost *atomic.Bool
}

func (l link) Read(p []byte) (int, error)  { return l.check(l.Conn.Read(p)) }
func (l link) Write(p []byte) (int, error) { return l.check(l.Conn.Write(p)) }
func (l link) Close() error                { l.lost.Store(true); return l.Conn.Close() }

func (l link) check(n int, err error) (int, error) {
	if err != nil {
		l.lost.Store(true)
	}
	return n, err
}

func connectToBastion(bastion *Bastion, lost *atomic.Bool) (*ssh.Client, error) {
	agentSock, err := getAgentSocket(bastion.Host)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSH agent socket: %w", err)
	}
	if agentSock == "" {
		return nil, fmt.Errorf("SSH agent socket not found (check -agent flag, .ssh/config IdentityAgent, or SSH_AUTH_SOCK)")
	}

	agentConn, err := net.Dial("unix", agentSock)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH agent: %w", err)
	}

	addr := net.JoinHostPort(bastion.Host, bastion.Port)
	config := &ssh.ClientConfig{
		User:              bastion.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers)},
		HostKeyCallback:   verifyHostKeyFingerprint(bastion),
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout:           10 * time.Second,
	}

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bastion %s: %w", bastion.Name, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(link{conn, lost}, addr, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to establish SSH connection to bastion %s: %w", bastion.Name, err)
	}

	// Handle server-sent global requests (e.g., keepalive@openssh.com)
	go func() {
		for req := range reqs {
			if req == nil {
				return
			}
			if req.Type == "keepalive@openssh.com" {
				req.Reply(true, nil)
			} else {
				req.Reply(false, nil)
			}
		}
	}()

	client := ssh.NewClient(sshConn, chans, nil)
	log.Printf("Connected to bastion %s (%s) - host key verified", bastion.Name, addr)
	return client, nil
}

func verifyHostKeyFingerprint(bastion *Bastion) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// SSH fingerprints must be in SHA256:base64 format (from ssh-keygen -lf)
		if !strings.HasPrefix(bastion.Fingerprint, "SHA256:") {
			return fmt.Errorf("bastion %s: fingerprint must be in SSH format (SHA256:base64), got: %s", bastion.Name, bastion.Fingerprint)
		}

		expectedBase64 := strings.TrimPrefix(bastion.Fingerprint, "SHA256:")
		// SHA256 is 32 bytes = 43 base64 characters (without padding)
		if len(expectedBase64) != 43 {
			return fmt.Errorf("bastion %s: invalid fingerprint length (expected 43 base64 chars, got %d)", bastion.Name, len(expectedBase64))
		}

		hash := sha256.Sum256(key.Marshal())
		calculatedBase64 := base64.RawStdEncoding.EncodeToString(hash[:])

		if calculatedBase64 != expectedBase64 {
			return fmt.Errorf("host key verification failed for %s: got SHA256:%s, expected %s", bastion.Name, calculatedBase64, bastion.Fingerprint)
		}

		log.Printf("Host key verified for bastion %s: SHA256:%s", bastion.Name, calculatedBase64)
		return nil
	}
}

// reconnect tries each bastion in turn, starting after the current one.
// Its only caller is Connect, which sets bc.reconnecting first.
func (bc *Connection) reconnect() {
	bc.dropMuxer()

	log.Printf("Connecting bastion set %s...", bc.setName)

	// Try each bastion in order (round-robin)
	for i := 0; i < len(bc.bastions); i++ {
		// Move to next bastion in shuffled list
		bc.mu.Lock()
		bc.currentIndex = (bc.currentIndex + 1) % len(bc.bastions)
		nextIndex := bc.currentIndex
		bc.mu.Unlock()

		bastion := &bc.bastions[nextIndex]
		lost := new(atomic.Bool)
		client, err := connectToBastion(bastion, lost)
		if err != nil {
			log.Printf("Retry %d/%d: Failed to connect to bastion %s: %v", i+1, len(bc.bastions), bastion.Name, err)
			time.Sleep(time.Duration(1+i) * time.Second) // Exponential backoff
			continue
		}

		bc.mu.Lock()
		bc.client, bc.lost = client, lost
		bc.reconnecting = false
		close(bc.readyCh)
		bc.mu.Unlock()

		log.Printf("Successfully connected bastion set %s to %s (%d/%d)", bc.setName, bastion.Name, nextIndex+1, len(bc.bastions))
		return
	}

	bc.mu.Lock()
	bc.reconnecting = false
	bc.mu.Unlock()

	log.Printf("Failed to connect bastion set %s after trying all %d bastions", bc.setName, len(bc.bastions))
}

func (bc *Connection) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	bc.mu.RLock()
	client := bc.live()
	bc.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("no active connection to bastion set %s", bc.setName)
	}

	conn, err := client.Dial(network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s via bastion set %s: %w", addr, bc.setName, err)
	}

	return conn, nil
}

// live returns bc.client, or nil if its link is lost. The caller must
// hold bc.mu.
func (bc *Connection) live() *ssh.Client {
	if bc.client == nil || bc.lost.Load() {
		return nil
	}
	return bc.client
}

func (bc *Connection) IsConnected() bool {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.live() != nil
}

func (bc *Connection) WaitReady() <-chan struct{} {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.readyCh
}

func (bc *Connection) Close() {
	close(bc.stopCh)
	bc.dropMuxer()

	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Leave client set. Closing it marks its link lost, so live returns
	// nil, and Connect must find it to know that readyCh needs replacing.
	if bc.client != nil {
		bc.client.Close()
	}
}

// getAgentSocket resolves the SSH agent socket path for a given hostname.
// Precedence order (highest to lowest):
// 1. -agent flag (agentSocket global variable from main.go)
// 2. .ssh/config IdentityAgent setting (via ssh -G)
// 3. SSH_AUTH_SOCK environment variable
func getAgentSocket(hostname string) (string, error) {
	// 1. Check -agent flag (highest precedence)
	if agentSocket != "" {
		return agentSocket, nil
	}

	// 2. Try to get IdentityAgent from ssh -G
	identityAgent, err := getIdentityAgentFromSSHConfig(hostname)
	if err != nil {
		// If ssh -G fails, fall back to SSH_AUTH_SOCK
		log.Printf("Warning: ssh -G failed for %s: %v, falling back to SSH_AUTH_SOCK", hostname, err)
		return os.Getenv("SSH_AUTH_SOCK"), nil
	}

	// Handle special values
	if identityAgent == "" || identityAgent == "none" {
		// Not set or explicitly disabled, use SSH_AUTH_SOCK
		return os.Getenv("SSH_AUTH_SOCK"), nil
	}

	if identityAgent == "SSH_AUTH_SOCK" {
		// Explicitly set to use the environment variable
		return os.Getenv("SSH_AUTH_SOCK"), nil
	}

	// ssh -G has already expanded paths (e.g., ~ to home directory)
	// so we can use the value directly
	return identityAgent, nil
}

// getIdentityAgentFromSSHConfig uses `ssh -G` to resolve the IdentityAgent setting
// for a given hostname from .ssh/config files.
func getIdentityAgentFromSSHConfig(hostname string) (string, error) {
	cmd := exec.Command("ssh", "-G", hostname)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ssh -G %s failed: %w", hostname, err)
	}

	// Use regex to find `identityagent` value
	matches := identityAgentRegex.FindSubmatch(output)
	if len(matches) > 1 {
		return string(matches[1]), nil
	}

	// identityagent not found in output, return empty string
	return "", nil
}
