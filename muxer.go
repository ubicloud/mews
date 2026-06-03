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

// sshMuxer is the SSH-transport layer of the muxer tower. It owns one SSH
// session and the mux.Mux that frames many streams over that session's
// stdio. It exists to bundle the three things that live and die together --
// the session, its stdin, and the Mux -- so that one Close tears the whole
// session down in order. One per Connection, started lazily by getOrCreateMuxer
// and dropped by dropMuxer (see bastion.go).
//
// Layer tower:
//
//	Connection  owns the *ssh.Client and caches one sshMuxer (bc.sshMuxer)
//	  sshMuxer  owns one ssh.Session + its stdin + one mux.Mux   (this type)
//	    mux.Mux frames/demuxes many streams over the session stdio
//	      mux.Stream  one logical stream per upstream dial
//	        streamConn  adapts a mux.Stream to net.Conn for http.Transport
type sshMuxer struct {
	sess  *ssh.Session
	stdin io.WriteCloser
	m     *mux.Mux
}

// Close is nil-safe so callers can fire it unconditionally. Order matters:
// stdin first signals EOF to the bastion relay, then the Mux wakes any
// blocked streams, then the session is torn down.
func (r *sshMuxer) Close() {
	r.stdin.Close()
	r.m.Close()
	r.sess.Close()
}

// getOrCreateMuxer returns the live Mux, starting one lazily on first call.
// Reconnects invalidate the cached sshMuxer via dropMuxer (see bastion.go).
func (bc *Connection) getOrCreateMuxer() (*mux.Mux, error) {
	bc.muxerMu.Lock()
	defer bc.muxerMu.Unlock()

	// Reuse the live muxer if one's already up.
	if bc.sshMuxer != nil {
		return bc.sshMuxer.m, nil
	}
	// Otherwise start one lazily on the current client.
	bc.mu.RLock()
	client := bc.client
	bc.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("bastion set %s: not connected", bc.setName)
	}
	sm, err := startMuxer(client, bc.setName)
	if err != nil {
		return nil, err
	}
	bc.sshMuxer = sm
	return sm.m, nil
}

// dropMuxer tears down and clears the cached sshMuxer (which closes the SSH
// session). Safe on a Connection that never started one; the clear is what
// lets the next getOrCreateMuxer rebuild on a fresh client after a reconnect.
func (bc *Connection) dropMuxer() {
	bc.muxerMu.Lock()
	if bc.sshMuxer != nil {
		bc.sshMuxer.Close()
		bc.sshMuxer = nil
	}
	bc.muxerMu.Unlock()
}

func muxerDialer(conn *Connection) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {

		// Dial normally if muxer is false.
		conn.mu.RLock()
		muxer := conn.bastions[conn.currentIndex].Muxer
		conn.mu.RUnlock()
		if !muxer {
			return conn.Dial(ctx, network, addr)
		}

		// Begin muxer setup.
		m, err := conn.getOrCreateMuxer()
		if err != nil {
			return nil, err
		}
		// Muxer protocol uses "$IP $port" with the space in the middle.
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		s, err := m.Open([]byte(host + " " + port))
		if err != nil {
			return nil, fmt.Errorf("muxer dial via bastion set %s: %w", conn.setName, err)
		}

		return streamConn{s}, nil
	}
}

// startMuxer opens one SSH session, runs sshd's ForceCommand relay, and
// returns an sshMuxer over its stdio.
func startMuxer(client *ssh.Client, setName string) (*sshMuxer, error) {
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
	return &sshMuxer{sess: sess, stdin: stdin, m: mux.NewRW(stdout, stdin)}, nil
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

// mux has no deadline mechanism; these are no-ops. Transport timeouts that
// rely on SetDeadline won't apply to mux streams.
func (streamConn) LocalAddr() net.Addr              { return muxAddr{} }
func (streamConn) RemoteAddr() net.Addr             { return muxAddr{} }
func (streamConn) SetDeadline(time.Time) error      { return nil }
func (streamConn) SetReadDeadline(time.Time) error  { return nil }
func (streamConn) SetWriteDeadline(time.Time) error { return nil }

type muxAddr struct{}

func (muxAddr) Network() string { return "mux" }
func (muxAddr) String() string  { return "mux" }
