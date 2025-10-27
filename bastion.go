package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

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
	readyOnce    sync.Once
}

func NewConnection(setName string, bastions []Bastion) *Connection {
	// Shuffle bastions for random load distribution
	shuffled := make([]Bastion, len(bastions))
	copy(shuffled, bastions)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	return &Connection{
		setName:      setName,
		bastions:     shuffled,
		currentIndex: 0,
		stopCh:       make(chan struct{}),
		readyCh:      make(chan struct{}),
	}
}

func (bc *Connection) Connect() error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.client != nil {
		return nil // Already connected
	}

	if len(bc.bastions) == 0 {
		return fmt.Errorf("no bastions available in set %s", bc.setName)
	}

	bastion := &bc.bastions[bc.currentIndex]
	client, err := connectToBastion(bastion)
	if err != nil {
		log.Printf("Failed to connect to bastion %s in set %s: %v", bastion.Name, bc.setName, err)
		return err
	}

	bc.client = client
	log.Printf("Established connection to bastion set %s via %s (%d/%d)", bc.setName, bastion.Name, bc.currentIndex+1, len(bc.bastions))

	// Signal that connection is ready (only once)
	bc.readyOnce.Do(func() { close(bc.readyCh) })

	return nil
}

func connectToBastion(bastion *Bastion) (*ssh.Client, error) {
	agentSock := os.Getenv("SSH_AUTH_SOCK")
	if agentSock == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK not set, SSH agent required")
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

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
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

func (bc *Connection) reconnect() {
	bc.mu.Lock()
	if bc.reconnecting {
		bc.mu.Unlock()
		return // Already reconnecting
	}
	bc.reconnecting = true

	// Close dead connection
	oldIndex := bc.currentIndex
	oldBastion := bc.bastions[oldIndex].Name
	if bc.client != nil {
		bc.client.Close()
		bc.client = nil
	}
	bc.mu.Unlock()

	log.Printf("Reconnecting bastion set %s (was connected to %s)...", bc.setName, oldBastion)

	// Try each bastion in order (round-robin)
	for i := 0; i < len(bc.bastions); i++ {
		// Move to next bastion in shuffled list
		bc.mu.Lock()
		bc.currentIndex = (bc.currentIndex + 1) % len(bc.bastions)
		nextIndex := bc.currentIndex
		bc.mu.Unlock()

		bastion := &bc.bastions[nextIndex]
		client, err := connectToBastion(bastion)
		if err != nil {
			log.Printf("Retry %d/%d: Failed to connect to bastion %s: %v", i+1, len(bc.bastions), bastion.Name, err)
			time.Sleep(time.Duration(1+i) * time.Second) // Exponential backoff
			continue
		}

		bc.mu.Lock()
		bc.client = client
		bc.reconnecting = false
		bc.mu.Unlock()

		log.Printf("Successfully reconnected bastion set %s to %s (%d/%d)", bc.setName, bastion.Name, nextIndex+1, len(bc.bastions))
		return
	}

	bc.mu.Lock()
	bc.reconnecting = false
	bc.mu.Unlock()

	log.Printf("Failed to reconnect bastion set %s after trying all %d bastions", bc.setName, len(bc.bastions))
}

func (bc *Connection) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	bc.mu.RLock()
	client := bc.client
	bc.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("no active connection to bastion set %s", bc.setName)
	}

	conn, err := client.Dial(network, addr)
	if err != nil {
		// Only trigger reconnect if the error suggests the SSH connection is dead
		// Don't reconnect for application-level errors like "connection refused" or "missing port"
		if strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset") {
			go bc.reconnect()
		}
		return nil, fmt.Errorf("failed to dial %s via bastion set %s: %w", addr, bc.setName, err)
	}

	return conn, nil
}

func (bc *Connection) IsConnected() bool {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.client != nil
}

func (bc *Connection) WaitReady() <-chan struct{} {
	return bc.readyCh
}

func (bc *Connection) Close() {
	close(bc.stopCh)

	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.client != nil {
		bc.client.Close()
		bc.client = nil
	}
}
