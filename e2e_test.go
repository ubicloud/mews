package main

// These tests run a real mews Server and Connection against a stand-in
// bastion that speaks both direct-tcpip and the funpipe relay. A TCP relay
// in front of each bastion breaks the link as a laptop's sleep does.

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const e2eBody = "hello-from-bmc"

// e2eRelay stands in for the network between mews and one bastion.
type e2eRelay struct {
	ln       net.Listener
	target   string
	mu       sync.Mutex
	conns    []net.Conn
	zombies  []*atomic.Bool
	down     bool
	gate     chan struct{}
	accepted atomic.Int32
}

func newE2ERelay(t *testing.T, target string) *e2eRelay {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &e2eRelay{ln: ln, target: target}
	go r.serve()
	t.Cleanup(func() { ln.Close(); r.cut() })
	return r
}

func (r *e2eRelay) port() string { return strconv.Itoa(r.ln.Addr().(*net.TCPAddr).Port) }

func (r *e2eRelay) serve() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		r.mu.Lock()
		down, gate := r.down, r.gate
		r.mu.Unlock()
		if down {
			c.Close()
			continue
		}
		if gate != nil {
			<-gate
		}
		u, err := net.Dial("tcp", r.target)
		if err != nil {
			c.Close()
			continue
		}
		r.accepted.Add(1)
		zombie := new(atomic.Bool)
		r.mu.Lock()
		r.conns = append(r.conns, c, u)
		r.zombies = append(r.zombies, zombie)
		r.mu.Unlock()
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := c.Read(buf)
				if zombie.Load() {
					// The bastion has forgotten this connection, so answer with a reset.
					c.(*net.TCPConn).SetLinger(0)
					c.Close()
					return
				}
				if n > 0 {
					u.Write(buf[:n])
				}
				if err != nil {
					u.Close()
					return
				}
			}
		}()
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := u.Read(buf)
				if zombie.Load() {
					return
				}
				if n > 0 {
					c.Write(buf[:n])
				}
				if err != nil {
					c.Close()
					return
				}
			}
		}()
	}
}

// zombify simulates a laptop waking up: the bastion has dropped each connection,
// but mews has not heard, so the next bytes mews sends get a reset.
func (r *e2eRelay) zombify() {
	r.mu.Lock()
	defer r.mu.Unlock()
	// conns holds pairs: the mews side, then the bastion side.
	for i, z := range r.zombies {
		z.Store(true)
		r.conns[2*i+1].Close()
	}
}

// cut resets every live link at once, so mews sees "connection reset by
// peer" without having to send anything.
func (r *e2eRelay) cut() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.conns {
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
		c.Close()
	}
	r.conns = nil
	r.zombies = nil
}

// setDown(true) makes new connections fail, as if the bastion were
// unreachable; setDown(false) lets them through again.
func (r *e2eRelay) setDown(down bool) {
	r.mu.Lock()
	r.down = down
	r.mu.Unlock()
}

// hold makes new connections wait until release is called.
func (r *e2eRelay) hold() (release func()) {
	gate := make(chan struct{})
	r.mu.Lock()
	r.gate = gate
	r.mu.Unlock()
	return func() { close(gate) }
}

// e2eBastionServer stands in for the bastion's sshd. It accepts "none"
// auth, forwards direct-tcpip, and runs a funpipe relay when a session
// requests a shell.
type e2eBastionServer struct {
	ln       net.Listener
	config   *ssh.ServerConfig
	hostKey  ssh.Signer
	mu       sync.Mutex
	sessions []ssh.Channel
}

func newE2EBastionServer(t *testing.T) *e2eBastionServer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &e2eBastionServer{ln: ln, config: cfg, hostKey: signer}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *e2eBastionServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *e2eBastionServer) handle(nc net.Conn) {
	sc, chans, reqs, err := ssh.NewServerConn(nc, s.config)
	if err != nil {
		nc.Close()
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		switch nch.ChannelType() {
		case "direct-tcpip":
			var p struct {
				Host       string
				Port       uint32
				OriginHost string
				OriginPort uint32
			}
			if err := ssh.Unmarshal(nch.ExtraData(), &p); err != nil {
				nch.Reject(ssh.ConnectionFailed, "bad payload")
				continue
			}
			tc, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
			if err != nil {
				nch.Reject(ssh.ConnectionFailed, err.Error())
				continue
			}
			ch, chReqs, err := nch.Accept()
			if err != nil {
				tc.Close()
				continue
			}
			go ssh.DiscardRequests(chReqs)
			go func() { io.Copy(ch, tc); ch.CloseWrite() }()
			go func() { io.Copy(tc, ch); tc.(*net.TCPConn).CloseWrite() }()
		case "session":
			ch, chReqs, err := nch.Accept()
			if err != nil {
				continue
			}
			go func() {
				for req := range chReqs {
					if req.Type == "shell" {
						req.Reply(true, nil)
						s.mu.Lock()
						s.sessions = append(s.sessions, ch)
						s.mu.Unlock()
						go serveFunpipe(ch)
						continue
					}
					req.Reply(false, nil)
				}
			}()
		default:
			nch.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

// killSessions ends the relay sessions but keeps the SSH transport up.
func (s *e2eBastionServer) killSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.sessions {
		ch.Close()
	}
	s.sessions = nil
}

// serveFunpipe is the bastion side of internal/mux. OPEN "host port" dials
// the destination, DATA is copied to it, and FIN half-closes it. Incoming WIN
// is ignored, since the bastion never runs out of window in these tests, but
// every DATA it consumes is credited back.
func serveFunpipe(ch ssh.Channel) {
	const (
		kindOpen, kindData, kindWin = 0, 1, 2
		flagFin                     = 1
	)
	var wmu sync.Mutex
	send := func(kind, flags byte, id uint32, p []byte) {
		buf := make([]byte, 8+len(p))
		buf[0], buf[1] = kind, flags
		binary.BigEndian.PutUint32(buf[2:6], id)
		binary.BigEndian.PutUint16(buf[6:8], uint16(len(p)))
		copy(buf[8:], p)
		wmu.Lock()
		ch.Write(buf)
		wmu.Unlock()
	}
	var mu sync.Mutex
	conns := map[uint32]net.Conn{}
	defer func() {
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		ch.Close()
	}()
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(ch, hdr); err != nil {
			return
		}
		kind, flags := hdr[0], hdr[1]
		id := binary.BigEndian.Uint32(hdr[2:6])
		p := make([]byte, binary.BigEndian.Uint16(hdr[6:8]))
		if _, err := io.ReadFull(ch, p); err != nil {
			return
		}
		switch kind {
		case kindOpen:
			host, port, _ := strings.Cut(string(p), " ")
			tc, err := net.Dial("tcp", net.JoinHostPort(host, port))
			if err != nil {
				send(kindData, flagFin, id, nil)
				continue
			}
			mu.Lock()
			conns[id] = tc
			mu.Unlock()
			go func() {
				buf := make([]byte, 16*1024)
				for {
					n, err := tc.Read(buf)
					if n > 0 {
						send(kindData, 0, id, buf[:n])
					}
					if err != nil {
						send(kindData, flagFin, id, nil)
						return
					}
				}
			}()
		case kindData:
			mu.Lock()
			tc := conns[id]
			mu.Unlock()
			if tc == nil {
				continue
			}
			if len(p) > 0 {
				tc.Write(p)
				var d [4]byte
				binary.BigEndian.PutUint32(d[:], uint32(len(p)))
				send(kindWin, 0, id, d[:])
			}
			if flags&flagFin != 0 {
				tc.(*net.TCPConn).CloseWrite()
			}
		}
	}
}

type e2eSite struct {
	t        *testing.T
	front    string
	ps       *Server
	relays   []*e2eRelay
	servers  []*e2eBastionServer
	slowOnce atomic.Bool
	slowIn   chan struct{}
	slowGo   chan struct{}
}

// newE2ESite builds n bastions (in config order) for one set "dc", an HTTPS
// upstream behind them, and a mews Server in front.
func newE2ESite(t *testing.T, protocol Protocol, n int) *e2eSite {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	aln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aln.Close() })
	keyring := agent.NewKeyring()
	go func() {
		for {
			c, err := aln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(keyring, c)
		}
	}()
	oldSock := agentSocket
	agentSocket = sock
	t.Cleanup(func() { agentSocket = oldSock })

	s := &e2eSite{t: t, slowIn: make(chan struct{}), slowGo: make(chan struct{})}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /slow blocks its first call until released, to hold a request
		// in flight while the link breaks.
		if r.URL.Path == "/slow" && s.slowOnce.CompareAndSwap(false, true) {
			close(s.slowIn)
			<-s.slowGo
		}
		fmt.Fprint(w, e2eBody)
	}))
	t.Cleanup(func() {
		select {
		case <-s.slowGo:
		default:
			close(s.slowGo)
		}
		up.Close()
	})

	var bastions []Bastion
	for i := 0; i < n; i++ {
		srv := newE2EBastionServer(t)
		relay := newE2ERelay(t, srv.ln.Addr().String())
		s.servers = append(s.servers, srv)
		s.relays = append(s.relays, relay)
		bastions = append(bastions, Bastion{
			Name:        fmt.Sprintf("b%d", i),
			Host:        "127.0.0.1",
			Port:        relay.port(),
			User:        "test",
			Fingerprint: ssh.FingerprintSHA256(srv.hostKey.PublicKey()),
			Protocol:    protocol,
		})
	}
	cfg := &Config{
		BastionSets: map[string][]Bastion{"dc": bastions},
		Upstreams: []Upstream{{
			Local:       "bmc1.localhost",
			Remote:      up.URL,
			BastionSet:  "dc",
			Fingerprint: calculateFingerprint(up.Certificate()),
		}},
	}
	s.ps = NewServer(cfg, "6189")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// http.Server.Close does not wait for handlers, so a /__wait that
	// never returns cannot hang the test.
	hs := &http.Server{Handler: s.ps}
	go hs.Serve(ln)
	s.front = "http://" + ln.Addr().String()
	t.Cleanup(func() { hs.Close(); s.ps.Close() })
	return s
}

func (s *e2eSite) get(path string) (outcome string, detail string) {
	return s.do("GET", path)
}

// do sends a request for host bmc1.localhost as a browser would, following
// redirects, and classifies what the user sees: "waiting" for the waiting
// page, "ok" for the upstream's body, and "error" for anything else.
func (s *e2eSite) do(method, path string) (outcome string, detail string) {
	client := &http.Client{Timeout: 10 * time.Second}
	var reqBody io.Reader
	if method == "POST" {
		reqBody = strings.NewReader("power=cycle")
	}
	req, _ := http.NewRequest(method, s.front+path, reqBody)
	req.Host = "bmc1.localhost"
	resp, err := client.Do(req)
	if err != nil {
		return "error", err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	switch {
	case strings.Contains(body, e2eBody):
		return "ok", body
	case strings.Contains(body, "Touch your key"):
		return "waiting", ""
	}
	return "error", fmt.Sprintf("%d %s", resp.StatusCode, strings.TrimSpace(body))
}

func (s *e2eSite) mustGet(path string, want ...string) string {
	s.t.Helper()
	got, detail := s.get(path)
	for _, w := range want {
		if got == w {
			return got
		}
	}
	s.t.Fatalf("GET %s: got %s (%s), want one of %v", path, got, detail, want)
	return ""
}

// ready reports whether /__wait says "ready" within d. A waiting page reloads
// on that message, so it must not come while the set is down.
func (s *e2eSite) ready(d time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	for ctx.Err() == nil {
		req, _ := http.NewRequestWithContext(ctx, "GET", s.front+"/__wait?set=dc", nil)
		req.Host = "localhost"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		if resp.StatusCode == http.StatusNotFound {
			// The set does not exist until a request has created it.
			resp.Body.Close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if sc.Text() == "data: ready" {
				resp.Body.Close()
				return true
			}
		}
		resp.Body.Close()
		return false
	}
	return false
}

func (s *e2eSite) mustReady() {
	s.t.Helper()
	if !s.ready(10 * time.Second) {
		s.t.Fatal("/__wait never said ready")
	}
}

// waitFor fails the test unless cond becomes true within 10 seconds.
func (s *e2eSite) waitFor(what string, cond func() bool) {
	s.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			s.t.Fatalf("timed out waiting until %s", what)
		}
	}
}

func (s *e2eSite) conn() *Connection {
	s.ps.connMu.RLock()
	defer s.ps.connMu.RUnlock()
	return s.ps.connections["dc"]
}

// waitLost waits until mews has noticed that the link is gone.
func (s *e2eSite) waitLost() {
	s.t.Helper()
	s.waitFor("the set is down", func() bool { return !s.conn().IsConnected() })
}

// connect walks the first-visit flow: waiting page, ready, upstream.
func (s *e2eSite) connect() {
	s.t.Helper()
	s.mustGet("/", "waiting")
	s.mustReady()
	s.mustGet("/", "ok")
}

func forProtocols(t *testing.T, f func(t *testing.T, p Protocol)) {
	for _, p := range []Protocol{ProtocolDirectTCPIP, ProtocolFunpipe} {
		t.Run(string(p), func(t *testing.T) { f(t, p) })
	}
}

// The link dies while the laptop sleeps, and mews notices before the next
// request, which must get the waiting page.
func TestE2EReopenAfterSleep(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		s := newE2ESite(t, p, 1)
		s.connect()
		s.relays[0].cut()
		s.waitLost()
		s.mustGet("/", "waiting")
		s.mustReady()
		s.mustGet("/", "ok")
	})
}

// As above, but the next request comes at once, perhaps before mews has
// noticed.
func TestE2EReopenFirstRequest(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		s := newE2ESite(t, p, 1)
		s.connect()
		s.relays[0].cut()
		if s.mustGet("/", "waiting", "ok") == "waiting" {
			s.mustReady()
		}
		s.mustGet("/", "ok")
	})
}

// A request is in flight when the link dies.
func TestE2EInFlight(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		s := newE2ESite(t, p, 1)
		s.connect()
		res := make(chan string, 1)
		go func() { o, d := s.get("/slow"); res <- o + " " + d }()
		<-s.slowIn
		s.relays[0].cut()
		got := <-res
		if !strings.HasPrefix(got, "waiting") && !strings.HasPrefix(got, "ok") {
			t.Fatalf("in-flight GET: %s", got)
		}
		if strings.HasPrefix(got, "waiting") {
			s.mustReady()
		}
		s.mustGet("/", "ok")
	})
}

// When the bastion in use goes down, mews fails over to the other one.
func TestE2EFailover(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		s := newE2ESite(t, p, 2)
		s.connect()
		first := 0
		if s.relays[1].accepted.Load() > 0 {
			first = 1
		}
		other := 1 - first
		s.relays[first].setDown(true)
		s.relays[first].cut()
		s.waitLost()
		if s.mustGet("/", "waiting", "ok") == "waiting" {
			s.mustReady()
		}
		s.mustGet("/", "ok")
		if s.relays[other].accepted.Load() == 0 {
			t.Fatal("did not fail over to the other bastion")
		}
	})
}

// With every bastion down, the waiting page must wait (not reload in a
// loop), and a later visit must try again once a bastion is back.
func TestE2ERetryAfterFailure(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		s := newE2ESite(t, p, 1)
		s.connect()
		s.relays[0].setDown(true)
		s.relays[0].cut()
		s.waitLost()
		s.mustGet("/", "waiting")
		if s.ready(3 * time.Second) {
			t.Fatal("/__wait said ready while every bastion is down")
		}
		s.relays[0].setDown(false)
		if s.mustGet("/", "waiting", "ok") == "waiting" {
			s.mustReady()
		}
		s.mustGet("/", "ok")
	})
}

// Only the funpipe relay session ends; the SSH transport stays up.
func TestE2ERelaySessionEnds(t *testing.T) {
	s := newE2ESite(t, ProtocolFunpipe, 1)
	s.connect()
	s.servers[0].killSessions()
	c := s.conn()
	s.waitFor("the relay session has ended", func() bool {
		c.muxerMu.Lock()
		defer c.muxerMu.Unlock()
		return c.sshMuxer == nil || c.sshMuxer.m.Closed()
	})
	if s.mustGet("/", "waiting", "ok") == "waiting" {
		s.mustReady()
	}
	s.mustGet("/", "ok")
}

// Many requests race the break, and the set must reconnect only once. A
// healthy link must carry concurrent requests without reconnecting.
func TestE2EBurst(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		s := newE2ESite(t, p, 1)
		s.connect()
		var wg sync.WaitGroup
		burst := func(want ...string) {
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					got, detail := s.get("/")
					for _, w := range want {
						if got == w {
							return
						}
					}
					t.Errorf("burst GET: %s (%s)", got, detail)
				}()
			}
			wg.Wait()
		}
		burst("ok")
		s.relays[0].cut()
		burst("waiting", "ok")
		s.mustReady()
		burst("ok")
		c := s.conn()
		c.mu.RLock()
		reconnecting := c.reconnecting
		c.mu.RUnlock()
		if reconnecting {
			t.Fatal("a second reconnect started after the burst")
		}
		if n := s.relays[0].accepted.Load(); n != 2 {
			t.Fatalf("relay accepted %d connections, want 2 (connect + one reconnect)", n)
		}
	})
}

// A POST is in flight when the link dies. The transport does not retry a
// POST, so the error surfaces mid-request rather than at the next dial.
func TestE2EInFlightPost(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		s := newE2ESite(t, p, 1)
		s.connect()
		res := make(chan string, 1)
		go func() { o, d := s.do("POST", "/slow"); res <- o + " " + d }()
		<-s.slowIn
		s.relays[0].cut()
		got := <-res
		if !strings.HasPrefix(got, "waiting") && !strings.HasPrefix(got, "ok") {
			t.Fatalf("in-flight POST: %s", got)
		}
		if strings.HasPrefix(got, "waiting") {
			s.mustReady()
		}
		s.mustGet("/", "ok")
	})
}

// A held connection stands in for the wait while the person touches the
// key. Until the reconnect finishes, the waiting page must not be told
// "ready", or it reloads in a loop.
func TestE2ESlowReconnect(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		s := newE2ESite(t, p, 1)
		s.connect()
		release := s.relays[0].hold()
		s.relays[0].cut()
		s.waitLost()
		s.mustGet("/", "waiting")
		if s.ready(500 * time.Millisecond) {
			t.Fatal("/__wait said ready before the reconnect finished")
		}
		release()
		s.mustReady()
		s.mustGet("/", "ok")
	})
}

// One bastion of the set is down at startup, whichever one is tried first.
func TestE2EInitialFailover(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		for down := 0; down < 2; down++ {
			s := newE2ESite(t, p, 2)
			s.relays[down].setDown(true)
			s.mustGet("/", "waiting")
			s.mustReady()
			s.mustGet("/", "ok")
		}
	})
}

// The usual wake: mews learns that the link is dead only when the bytes of
// its next request get a reset. That request must still succeed or end on
// the waiting page, for a GET and for a POST, which is not retried.
func TestE2EWake(t *testing.T) {
	forProtocols(t, func(t *testing.T, p Protocol) {
		for _, method := range []string{"GET", "POST"} {
			t.Run(method, func(t *testing.T) {
				s := newE2ESite(t, p, 1)
				s.connect()
				s.relays[0].zombify()
				got, detail := s.do(method, "/")
				if got != "waiting" && got != "ok" {
					t.Fatalf("first %s after wake: %s (%s)", method, got, detail)
				}
				if got == "waiting" {
					s.mustReady()
				}
				s.mustGet("/", "ok")
			})
		}
	})
}
