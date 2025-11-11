package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Test SSH server
type testSSHServer struct {
	listener net.Listener
	config   *ssh.ServerConfig
	port     int
	mu       sync.Mutex
	stopped  bool
}

func newTestSSHServer(t *testing.T) *testSSHServer {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate host key: %v", err)
	}

	hostKey, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	s := &testSSHServer{
		listener: listener,
		config:   config,
		port:     listener.Addr().(*net.TCPAddr).Port,
	}

	go s.acceptConnections()
	return s
}

func (s *testSSHServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			stopped := s.stopped
			s.mu.Unlock()
			if stopped {
				return
			}
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *testSSHServer) handleConnection(netConn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.config)
	if err != nil {
		return
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "direct-tcpip" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}

		go ssh.DiscardRequests(requests)

		var payload struct {
			Host string
			Port uint32
		}
		if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
			channel.Close()
			continue
		}

		addr := fmt.Sprintf("%s:%d", payload.Host, payload.Port)
		targetConn, err := net.Dial("tcp", addr)
		if err != nil {
			channel.Close()
			continue
		}

		go io.Copy(channel, targetConn)
		go io.Copy(targetConn, channel)
	}
}

func (s *testSSHServer) Close() {
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	s.listener.Close()
}

// Test HTTPS server
type testHTTPSServer struct {
	server      *http.Server
	listener    net.Listener
	certificate *x509.Certificate
	url         string
}

func newTestHTTPSServer(t *testing.T, handler http.Handler) *testHTTPSServer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("Failed to create TLS listener: %v", err)
	}

	server := &http.Server{Handler: handler}
	go server.Serve(listener)

	return &testHTTPSServer{
		server:      server,
		listener:    listener,
		certificate: cert,
		url:         "https://" + listener.Addr().String(),
	}
}

func (s *testHTTPSServer) Fingerprint() string {
	return calculateFingerprint(s.certificate)
}

func (s *testHTTPSServer) Close() {
	s.server.Close()
	s.listener.Close()
}

// Test helpers
func mustDialSSH(t *testing.T, port int) *ssh.Client {
	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port), &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to dial SSH: %v", err)
	}
	return client
}

func startProxy(t *testing.T, cfg *Config, sshClients map[string]*ssh.Client) (int, *Server) {
	ps := NewServer(cfg, "6189")

	// Inject test SSH clients
	ps.connMu.Lock()
	for setName := range sshClients {
		readyCh := make(chan struct{})
		close(readyCh)
		conn := &Connection{}
		// Note: This is a test hack - in production, Connection is created properly
		ps.connections[setName] = conn
	}
	ps.connMu.Unlock()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port

	go http.Serve(listener, ps)
	time.Sleep(50 * time.Millisecond)

	return port, ps
}

func doProxyRequest(t *testing.T, port int, host string) string {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/", port), nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Host = host

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	return string(body)
}

// Tests
func TestStripPort(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com:6189", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:6189", "::1"},
		{"[::1]", "::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[fe80::1%eth0]:6189", "fe80::1%eth0"},
	}

	for _, tt := range tests {
		result := stripPort(tt.input)
		if result != tt.expected {
			t.Errorf("stripPort(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestMatchesWildcard(t *testing.T) {
	tests := []struct {
		pattern  string
		hostname string
		expected bool
	}{
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "bar.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "foo.bar.example.com", true},
		{"example.com", "example.com", false},
	}

	for _, tt := range tests {
		result := matchesWildcard(tt.pattern, tt.hostname)
		if result != tt.expected {
			t.Errorf("matchesWildcard(%q, %q) = %v, want %v", tt.pattern, tt.hostname, result, tt.expected)
		}
	}
}

func TestExtractSubdomain(t *testing.T) {
	tests := []struct {
		hostname string
		pattern  string
		expected string
	}{
		{"server1.example.com", "*.example.com", "server1"},
		{"server2.example.com", "*.example.com", "server2"},
		{"example.com", "*.example.com", ""},
		{"foo.bar.example.com", "*.example.com", "foo.bar"},
	}

	for _, tt := range tests {
		result := extractSubdomain(tt.hostname, tt.pattern)
		if result != tt.expected {
			t.Errorf("extractSubdomain(%q, %q) = %q, want %q", tt.hostname, tt.pattern, result, tt.expected)
		}
	}
}

func TestBuildUpstreamURL(t *testing.T) {
	tests := []struct {
		name     string
		upstream *Upstream
		hostname string
		expected string
		wantErr  bool
	}{
		{
			name:     "Simple URL without substitution",
			upstream: &Upstream{Remote: "https://10.1.1.1"},
			hostname: "bmc.localhost",
			expected: "https://10.1.1.1",
			wantErr:  false,
		},
		{
			name:     "Wildcard with subdomain substitution",
			upstream: &Upstream{Local: "*.dc1.localhost", Remote: "https://{subdomain}"},
			hostname: "server1.dc1.localhost",
			expected: "https://server1",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := buildUpstreamURL(tt.upstream, tt.hostname)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildUpstreamURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("buildUpstreamURL() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	configYAML := `
bastions:
  dc1:
    - name: "bastion-a"
      host: "bastion-a.example.com"
      fingerprint: "abc123"
upstreams:
  - local: "bmc1"
    remote: "https://10.1.1.1"
    bastion_set: "dc1"
    fingerprint: "abc123"
`

	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configYAML)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	cfg, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.BastionSets) != 1 || len(cfg.BastionSets["dc1"]) != 1 {
		t.Errorf("Expected 1 bastion set with 1 bastion")
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].Local != "bmc1.localhost" {
		t.Errorf("Expected 1 upstream with .localhost appended")
	}
}

func TestLoadConfig_MissingPin(t *testing.T) {
	configYAML := `
upstreams:
  - local: "bmc1"
    remote: "https://10.1.1.1"
`

	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configYAML)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	_, err = LoadConfig(tmpfile.Name())
	if err == nil {
		t.Fatal("Expected error for missing pin, got nil")
	}
	if !strings.Contains(err.Error(), "fingerprint is required") {
		t.Errorf("Expected error about missing pin, got: %v", err)
	}
}

func TestRewriteProtocolInResponse(t *testing.T) {
	// Create a test server
	ps := &Server{
		config:      &Config{},
		upstreams:   []Upstream{},
		port:        "6189",
		connections: make(map[string]*Connection),
		transports:  make(map[string]*http.Transport),
	}

	tests := []struct {
		name            string
		contentType     string
		contentEncoding string
		body            string
		hostname        string
		wantContains    []string
		wantNotContains []string
	}{
		{
			name:            "deflate compressed HTML with wss://",
			contentType:     "text/html",
			contentEncoding: "deflate",
			body:            `<script>var ws = new WebSocket("wss://" + window.location.host);</script>`,
			hostname:        "test.localhost:6189",
			wantContains:    []string{`"ws://"`, `window.location.host`},
			wantNotContains: []string{`"wss://"`},
		},
		{
			name:            "gzip compressed JavaScript with wss://",
			contentType:     "application/javascript;charset=UTF-8",
			contentEncoding: "gzip",
			body:            `const protocol = "wss:"; const url = protocol + "//" + host;`,
			hostname:        "test.localhost:6189",
			wantContains:    []string{`"ws:"`},
			wantNotContains: []string{`"wss:"`},
		},
		{
			name:            "deflate compressed with https:// for same hostname",
			contentType:     "text/html",
			contentEncoding: "deflate",
			body:            `<a href="https://test.localhost:6189/page">Link</a>`,
			hostname:        "test.localhost:6189",
			wantContains:    []string{`http://test.localhost:6189/page`},
			wantNotContains: []string{`https://test.localhost:6189`},
		},
		{
			name:            "no compression",
			contentType:     "text/html",
			contentEncoding: "",
			body:            `<script>new WebSocket('wss://example.com');</script>`,
			hostname:        "test.localhost:6189",
			wantContains:    []string{`'ws://example.com'`},
			wantNotContains: []string{`'wss://`},
		},
		{
			name:            "non-text content type (skip rewriting)",
			contentType:     "image/png",
			contentEncoding: "",
			body:            "binary image data",
			hostname:        "test.localhost:6189",
			wantContains:    []string{"binary image data"},
			wantNotContains: []string{},
		},
		{
			name:            "application/x-javascript content type",
			contentType:     "application/x-javascript",
			contentEncoding: "",
			body:            `var ws = new WebSocket("wss://example.com");`,
			hostname:        "test.localhost:6189",
			wantContains:    []string{`"ws://example.com"`},
			wantNotContains: []string{`"wss://`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock HTTP response
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Request: &http.Request{
					Host: tt.hostname,
					URL:  &url.URL{Path: "/test"},
				},
			}
			resp.Header.Set("Content-Type", tt.contentType)
			if tt.contentEncoding != "" {
				resp.Header.Set("Content-Encoding", tt.contentEncoding)
			}

			// Compress the body according to the content encoding
			var bodyReader io.Reader
			if tt.contentEncoding == "gzip" {
				var buf bytes.Buffer
				gzWriter := gzip.NewWriter(&buf)
				gzWriter.Write([]byte(tt.body))
				gzWriter.Close()
				bodyReader = &buf
			} else if tt.contentEncoding == "deflate" {
				var buf bytes.Buffer
				zlibWriter := zlib.NewWriter(&buf)
				zlibWriter.Write([]byte(tt.body))
				zlibWriter.Close()
				bodyReader = &buf
			} else {
				bodyReader = strings.NewReader(tt.body)
			}
			resp.Body = io.NopCloser(bodyReader)

			// Call the rewrite function
			err := ps.rewriteProtocolInResponse(resp)
			if err != nil {
				t.Fatalf("rewriteProtocolInResponse failed: %v", err)
			}

			// Read the modified response
			modifiedBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read modified body: %v", err)
			}
			modifiedStr := string(modifiedBody)

			// Check that expected strings are present
			for _, want := range tt.wantContains {
				if !strings.Contains(modifiedStr, want) {
					t.Errorf("Expected modified body to contain %q, got: %s", want, modifiedStr)
				}
			}

			// Check that unwanted strings are not present
			for _, notWant := range tt.wantNotContains {
				if strings.Contains(modifiedStr, notWant) {
					t.Errorf("Expected modified body to NOT contain %q, got: %s", notWant, modifiedStr)
				}
			}

			// Verify Content-Encoding header is removed
			if resp.Header.Get("Content-Encoding") != "" {
				t.Errorf("Expected Content-Encoding header to be removed, got: %s", resp.Header.Get("Content-Encoding"))
			}
		})
	}
}
