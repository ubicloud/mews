package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/ubicloud/mews/internal/mux"
)

// spawnMuxer runs muxer.py over stdin/stdout (simulating the SSH session
// channel) and returns the client-side Mux plus a cleanup func.
func spawnMuxer(t *testing.T) (*mux.Mux, func()) {
	t.Helper()
	cmd := exec.Command("python3", "muxer.py")
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	go io.Copy(io.Discard, stderr)
	m := mux.NewRW(stdout, stdin)
	return m, func() { stdin.Close(); m.Close(); cmd.Wait() }
}

// fetch sends an HTTP/1.1 GET / over the stream and returns the response body.
func fetch(t *testing.T, m *mux.Mux, addr string) string {
	t.Helper()
	s, err := m.Open([]byte(addr))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	host, _, _ := net.SplitHostPort(addr)
	fmt.Fprintf(s, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(s), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// TestMuxerEndToEnd: open N=8 concurrent streams to N distinct HTTP servers,
// each returning a unique body; verify all bodies arrive correctly.
func TestMuxerEndToEnd(t *testing.T) {
	const N = 8
	bodies := make([]string, N)
	servers := make([]*httptest.Server, N)
	for i := range bodies {
		body := fmt.Sprintf("upstream-%d", i)
		bodies[i] = body
		servers[i] = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, body)
		}))
		defer servers[i].Close()
	}
	m, cleanup := spawnMuxer(t)
	defer cleanup()

	var wg sync.WaitGroup
	got := make([]string, N)
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i] = fetch(t, m, strings.TrimPrefix(servers[i].URL, "http://"))
		}(i)
	}
	wg.Wait()
	for i := range bodies {
		if got[i] != bodies[i] {
			t.Errorf("stream %d: %q != %q", i, got[i], bodies[i])
		}
	}
}

// TestMuxerDeadUpstream: dial a port that has nothing listening. The relay's
// TCP dial fails, the relay closes its write half, our read sees EOF.
func TestMuxerDeadUpstream(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := l.Addr().String()
	l.Close()

	m, cleanup := spawnMuxer(t)
	defer cleanup()

	s, err := m.Open([]byte(deadAddr))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	n, err := s.Read(make([]byte, 1))
	if n != 0 || err != io.EOF {
		t.Fatalf("got (%d, %v), want (0, EOF)", n, err)
	}
}
