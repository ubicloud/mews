package main

// Host-namespace pivot. Some upstreams are reachable only from the bastion's
// host network namespace -- e.g. a BMC on an out-of-band network -- while the
// bastion sshd that mews connects to may terminate in a different namespace. A
// direct-tcpip dial would originate in the wrong namespace.
//
// Pivoting is opt-in per bastion, by the presence of pivot_command on the
// Bastion: when set, mews runs the embedded relay (mewsd.py) in one SSH
// session channel and carries traffic to it over direct-streamlocal@openssh.com
// channels, so the connection originates in the host namespace. pivot_command
// is the wrapper prepended to the relay (e.g. an nsenter into the host netns);
// the empty string runs the relay unwrapped. A bastion with no pivot_command
// is dialed with plain direct-tcpip.

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed mewsd.py
var relaySource string

// relayBlob is the relay source, base64-encoded so it survives the bastion's
// shell without any quoting hazard.
var relayBlob = base64.StdEncoding.EncodeToString([]byte(relaySource))

// pivot is a running host-namespace relay, owned by one bastion *ssh.Client.
type pivot struct {
	client *ssh.Client // the bastion connection this pivot was started on
	sess   *ssh.Session
	stdin  io.WriteCloser
	sock   string // socket path on the bastion
}

func (p *pivot) Close() error {
	if p.stdin != nil {
		p.stdin.Close() // -> relay sees stdin EOF -> exits, unlinks its socket
	}
	return p.sess.Close()
}

// bastionDialer returns the DialContext used by a bastion upstream's cached
// transport (and so by handleWebSocket, which dials through that transport).
// Whether a dial pivots is decided here, per dial, from the bastion currently
// in use: if it has a pivot_command the dial goes through a relay, else it
// falls through to conn.Dial. Resolving per dial means a reconnect to a
// different bastion in the set is honoured. The closure owns at most one
// relay, started lazily and rebuilt after a reconnect.
func bastionDialer(conn *Connection, local string) func(context.Context, string, string) (net.Conn, error) {
	var mu sync.Mutex
	var p *pivot

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn.mu.RLock()
		client := conn.client
		pivotCmd := conn.bastions[conn.currentIndex].PivotCommand
		conn.mu.RUnlock()

		// No pivot_command on the active bastion: plain direct-tcpip.
		if pivotCmd == nil {
			mu.Lock()
			if p != nil { // a previous bastion pivoted; this one does not
				p.Close()
				p = nil
			}
			mu.Unlock()
			return conn.Dial(ctx, network, addr)
		}

		if client == nil {
			return nil, fmt.Errorf("no active connection to bastion set %s", conn.setName)
		}

		mu.Lock()
		if p == nil || p.client != client { // first use, or bastion reconnected
			if p != nil {
				p.Close()
				p = nil
			}
			np, err := startPivot(client, conn.setName, local, addr, *pivotCmd)
			if err != nil {
				mu.Unlock()
				return nil, err
			}
			p = np
		}
		cur := p
		mu.Unlock()

		c, err := client.Dial("unix", cur.sock) // direct-streamlocal@openssh.com
		if err != nil {
			mu.Lock()
			if p == cur { // not already replaced: drop it, rebuilt on next call
				p.Close()
				p = nil
			}
			mu.Unlock()
			return nil, fmt.Errorf("pivot dial via bastion set %s failed: %w", conn.setName, err)
		}
		return c, nil
	}
}

// startPivot opens a session channel on client and runs the embedded relay,
// optionally wrapped by pivotCmd, blocking until the relay reports READY.
// local is the upstream's name (unique, used to name the socket); addr is its
// host:port connect address.
func startPivot(client *ssh.Client, setName, local, addr, pivotCmd string) (*pivot, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("pivot: bad upstream address %q: %w", addr, err)
	}

	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		sess.Close()
		return nil, err
	}

	// Keyed by the upstream name (unique per config) so two upstreams that
	// target the same host do not collide on one socket.
	sock := fmt.Sprintf("/tmp/mews-%d-%s.sock", os.Getpid(), strings.ReplaceAll(local, "/", "_"))

	// The leading `exec` collapses the bastion shell so the relay is a direct
	// child of (at most) the wrapper -- which keeps the relay's pidfd backstop
	// and channel-close reaping reliable. pivotCmd, if set, is spliced in
	// unquoted so the bastion shell word-splits it into argv.
	relay := fmt.Sprintf(
		`python3 -c "import base64,sys;exec(base64.b64decode('%s').decode())" %s %s %s`,
		relayBlob, sock, host, port)
	cmd := "exec "
	if pivotCmd = strings.TrimSpace(pivotCmd); pivotCmd != "" {
		cmd += pivotCmd + " "
	}
	cmd += relay

	if err := sess.Start(cmd); err != nil {
		sess.Close()
		return nil, err
	}

	// Wait for READY (relay has bound the socket). A bounded wait keeps a
	// broken wrapper from hanging the request that triggered the dial.
	br := bufio.NewReader(stdout)
	ready := make(chan string, 1)
	go func() {
		line, _ := br.ReadString('\n')
		ready <- line
	}()
	select {
	case line := <-ready:
		if !strings.HasPrefix(line, "READY") {
			detail, _ := io.ReadAll(io.LimitReader(stderr, 4096))
			sess.Close()
			return nil, fmt.Errorf("pivot relay via bastion set %s did not start: %s",
				setName, strings.TrimSpace(string(detail)))
		}
	case <-time.After(10 * time.Second):
		sess.Close()
		return nil, fmt.Errorf("pivot relay via bastion set %s timed out before READY", setName)
	}

	// Drain the rest so the relay never blocks writing to a full pipe.
	go io.Copy(io.Discard, br)
	go io.Copy(io.Discard, stderr)

	log.Printf("Pivot relay up for bastion set %s -> %s via %s", setName, addr, sock)
	return &pivot{client: client, sess: sess, stdin: stdin, sock: sock}, nil
}
