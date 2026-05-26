package main

// Session-channel muxer. For bastions whose sshd ForceCommand runs the mews
// mux relay (typically muxer.py or a wrapper around it), mews opens one SSH
// session channel per bastion *ssh.Client and treats its stdio as a stream
// multiplexer. Each upstream dial becomes one mux stream whose SYN payload
// is "host:port"; the bastion-side relay dials and splices.
//
// The relay is *not* shipped by mews. The bastion sysadmin installs it (or
// a wrapper that imports it) and points sshd ForceCommand at it. mews's only
// job is to ask sshd for a default session and speak the protocol.

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/ubicloud/mews/internal/mux"
	"golang.org/x/crypto/ssh"
)

type muxerRelay struct {
	sess  *ssh.Session
	stdin io.WriteCloser
	m     *mux.Mux
}

func (r *muxerRelay) Close() {
	if r == nil {
		return
	}
	r.stdin.Close()
	r.m.Close()
	r.sess.Close()
}

// acquireMuxer returns the live relay's Mux, starting one lazily on first
// call. Reconnects invalidate it via dropMuxer (see bastion.go).
func (bc *Connection) acquireMuxer() (*mux.Mux, error) {
	bc.muxerMu.Lock()
	defer bc.muxerMu.Unlock()
	if bc.relay != nil {
		return bc.relay.m, nil
	}
	bc.mu.RLock()
	client := bc.client
	bc.mu.RUnlock()
	if client == nil {
		return nil, fmt.Errorf("bastion set %s: not connected", bc.setName)
	}
	r, err := startMuxer(client, bc.setName)
	if err != nil {
		return nil, err
	}
	bc.relay = r
	return r.m, nil
}

func (bc *Connection) dropMuxer() {
	bc.muxerMu.Lock()
	bc.relay.Close()
	bc.relay = nil
	bc.muxerMu.Unlock()
}

func muxerDialer(conn *Connection) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		conn.mu.RLock()
		muxer := conn.bastions[conn.currentIndex].Muxer
		conn.mu.RUnlock()
		if !muxer {
			return conn.Dial(context.Background(), network, addr)
		}
		m, err := conn.acquireMuxer()
		if err != nil {
			return nil, err
		}
		s, err := m.Open([]byte(addr))
		if err != nil {
			return nil, fmt.Errorf("muxer dial via bastion set %s: %w", conn.setName, err)
		}
		return streamConn{s}, nil
	}
}

func startMuxer(client *ssh.Client, setName string) (*muxerRelay, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	stderr, _ := sess.StderrPipe()
	// Request the default session. sshd ForceCommand decides what runs.
	if err := sess.Shell(); err != nil {
		sess.Close()
		return nil, err
	}
	go func() {
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			log.Printf("[muxer %s] %s", setName, s.Text())
		}
	}()
	log.Printf("Muxer relay up for bastion set %s", setName)
	return &muxerRelay{sess: sess, stdin: stdin, m: mux.NewRW(stdout, stdin)}, nil
}

// streamConn adapts a mux.Stream into a net.Conn for http.Transport.
//
// net.Conn.Close must be a full close — concurrent Reads on the same conn
// have to return promptly. The embedded *mux.Stream supplies a proper Close
// that retires the stream; we don't shadow it. (The previous override
// returned CloseWrite only, which leaks the partner goroutine in any
// bidirectional io.Copy — most visibly, WebSocket handlers in proxy.go,
// since BMCs don't react to TCP half-close in WS mode.)
type streamConn struct{ *mux.Stream }

func (streamConn) LocalAddr() net.Addr              { return muxAddr{} }
func (streamConn) RemoteAddr() net.Addr             { return muxAddr{} }
func (streamConn) SetDeadline(time.Time) error      { return nil }
func (streamConn) SetReadDeadline(time.Time) error  { return nil }
func (streamConn) SetWriteDeadline(time.Time) error { return nil }

type muxAddr struct{}

func (muxAddr) Network() string { return "mux" }
func (muxAddr) String() string  { return "mux" }
