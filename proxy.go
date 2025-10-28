package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Server struct {
	config      *Config
	upstreams   []Upstream
	port        string
	connections map[string]*Connection
	connMu      sync.RWMutex
	transports  map[string]*http.Transport
	transportMu sync.RWMutex
}

func NewServer(cfg *Config, port string) *Server {
	return &Server{
		config:      cfg,
		upstreams:   cfg.Upstreams,
		port:        port,
		connections: make(map[string]*Connection),
		transports:  make(map[string]*http.Transport),
	}
}

func (ps *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	log.Printf("[%s] %s %s %s", start.Format(time.RFC3339), r.Method, r.Host, r.URL.Path)

	// SSE endpoint for connection status
	if r.URL.Path == "/__wait" {
		ps.handleSSEWait(w, r)
		return
	}

	// Show index page for root requests to proxy's own address
	listenAddr := "localhost:" + ps.port
	if r.URL.Path == "/" && (r.Host == listenAddr || r.Host == "" || strings.HasPrefix(r.Host, "127.0.0.1") || strings.HasPrefix(r.Host, "localhost")) {
		ps.handleIndex(w, r)
		return
	}

	upstream := findUpstream(ps.upstreams, r.Host)
	if upstream == nil {
		log.Printf("No upstream found for host: %s", r.Host)
		http.Error(w, "No upstream configured for this host", http.StatusNotFound)
		return
	}

	// Show waiting page if bastion connection not established yet
	if upstream.BastionSet != "" {
		ps.connMu.RLock()
		conn := ps.connections[upstream.BastionSet]
		ps.connMu.RUnlock()

		// Show waiting page if no connection exists yet, or if connecting
		if conn == nil || !conn.IsConnected() {
			// Start connection in background if not already started
			if conn == nil {
				go ps.startConnection(upstream.BastionSet)
			}
			ps.handleWaitingPage(w, upstream)
			return
		}
	}

	// Check if this is a WebSocket upgrade request
	if isWebSocketRequest(r) {
		log.Printf("WebSocket upgrade detected for %s%s", r.Host, r.URL.Path)
		ps.handleWebSocket(w, r, upstream)
		return
	}

	targetURL, err := buildUpstreamURL(upstream, r.Host)
	if err != nil {
		log.Printf("Error building upstream URL: %v", err)
		http.Error(w, "Invalid upstream configuration", http.StatusInternalServerError)
		return
	}

	transport, err := ps.getOrCreateTransport(upstream)
	if err != nil {
		log.Printf("Error getting transport: %v", err)
		http.Error(w, "Failed to create connection", http.StatusInternalServerError)
		return
	}

	proxy := ps.createReverseProxy(targetURL, transport)
	proxy.ServeHTTP(w, r)

	log.Printf("[%s] %s %s -> %s [completed in %s]", start.Format(time.RFC3339), r.Host, r.URL.Path, targetURL, time.Since(start))
}

func (ps *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "<h1>Mews</h1><table border=1><tr><th>Local<th>Remote<th>Bastion Set</tr>")
	for _, u := range ps.upstreams {
		link := fmt.Sprintf("http://%s:%s/", u.Local, ps.port)
		fmt.Fprintf(w, "<tr><td><a href=%q>%s</a><td>%s<td>%s</tr>", link, u.Local, u.Remote, u.BastionSet)
	}
	fmt.Fprintf(w, "</table>")
}

func (ps *Server) handleSSEWait(w http.ResponseWriter, r *http.Request) {
	bastionSet := r.URL.Query().Get("set")
	if bastionSet == "" {
		http.Error(w, "Missing set parameter", http.StatusBadRequest)
		return
	}
	ps.connMu.RLock()
	conn := ps.connections[bastionSet]
	ps.connMu.RUnlock()
	if conn == nil {
		http.Error(w, "Bastion set not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	if conn.IsConnected() {
		fmt.Fprintf(w, "data: ready\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return
	}

	<-conn.WaitReady()
	fmt.Fprintf(w, "data: ready\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (ps *Server) handleWaitingPage(w http.ResponseWriter, upstream *Upstream) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Connecting...</title></head><body>
<h1>Connecting to %s</h1>
<p>Waiting for SSH authentication to bastion set <strong>%s</strong>...</p>
<p><em>Touch your key if prompted</em></p>
<script>
new EventSource('/__wait?set=%s').onmessage = () => location.reload();
</script>
</body></html>`, upstream.Local, upstream.BastionSet, upstream.BastionSet)
}

func (ps *Server) getOrCreateTransport(upstream *Upstream) (*http.Transport, error) {
	// Check if transport already exists
	ps.transportMu.RLock()
	transport := ps.transports[upstream.Local]
	ps.transportMu.RUnlock()

	if transport != nil {
		return transport, nil
	}

	// Create new transport
	ps.transportMu.Lock()
	defer ps.transportMu.Unlock()

	// Double-check after acquiring write lock
	if transport := ps.transports[upstream.Local]; transport != nil {
		return transport, nil
	}

	// Parse remote URL to get hostname for TLS config
	parsedURL, err := url.Parse(upstream.Remote)
	if err != nil {
		return nil, err
	}

	hostname := stripPort(parsedURL.Host)
	tlsConfig := createTLSConfig(upstream, hostname)

	transport = &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	if upstream.BastionSet != "" {
		conn, err := ps.getOrCreateConnection(upstream.BastionSet)
		if err != nil {
			return nil, err
		}
		transport.DialContext = conn.Dial
		log.Printf("Created cached transport for %s via bastion set %s", upstream.Local, upstream.BastionSet)
	} else {
		log.Printf("Created cached transport for %s (direct connection)", upstream.Local)
	}

	ps.transports[upstream.Local] = transport
	return transport, nil
}

func (ps *Server) getOrCreateConnection(bastionSetName string) (*Connection, error) {
	ps.connMu.RLock()
	conn := ps.connections[bastionSetName]
	ps.connMu.RUnlock()

	if conn != nil {
		return conn, nil
	}

	ps.connMu.Lock()
	defer ps.connMu.Unlock()

	// Double-check after acquiring write lock
	if conn := ps.connections[bastionSetName]; conn != nil {
		return conn, nil
	}

	bastions, ok := ps.config.BastionSets[bastionSetName]
	if !ok {
		return nil, fmt.Errorf("bastion set %s not found", bastionSetName)
	}

	conn = NewConnection(bastionSetName, bastions)
	if err := conn.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to bastion set %s: %w", bastionSetName, err)
	}

	ps.connections[bastionSetName] = conn
	return conn, nil
}

// startConnection initiates a bastion connection in the background
func (ps *Server) startConnection(bastionSetName string) {
	// Check if already being created
	ps.connMu.RLock()
	if ps.connections[bastionSetName] != nil {
		ps.connMu.RUnlock()
		return
	}
	ps.connMu.RUnlock()

	ps.connMu.Lock()
	// Double-check
	if ps.connections[bastionSetName] != nil {
		ps.connMu.Unlock()
		return
	}

	bastions, ok := ps.config.BastionSets[bastionSetName]
	if !ok {
		ps.connMu.Unlock()
		log.Printf("Bastion set %s not found", bastionSetName)
		return
	}

	// Create connection object and add to map immediately
	// This prevents duplicate connection attempts
	log.Printf("Starting connection to bastion set %s...", bastionSetName)
	conn := NewConnection(bastionSetName, bastions)
	ps.connections[bastionSetName] = conn
	ps.connMu.Unlock()

	// Connect OUTSIDE the lock to avoid blocking other requests
	// This allows requests to other bastions to proceed while waiting for YubiKey touch
	if err := conn.Connect(); err != nil {
		log.Printf("Failed to connect to bastion set %s: %v", bastionSetName, err)
		return
	}

	log.Printf("Successfully connected to bastion set %s", bastionSetName)
}

func (ps *Server) createReverseProxy(targetURL string, transport *http.Transport) *httputil.ReverseProxy {
	target, _ := url.Parse(targetURL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = transport
	proxy.ErrorHandler = ps.handleProxyError
	proxy.ModifyResponse = ps.rewriteProtocolInResponse
	return proxy
}

// rewriteProtocolInResponse rewrites wss:// to ws:// and https:// to http:// in HTML/JS responses
// This allows BMC JavaScript that expects HTTPS to work over plain HTTP
func (ps *Server) rewriteProtocolInResponse(resp *http.Response) error {
	contentType := resp.Header.Get("Content-Type")

	// Only rewrite text-based content that might contain WebSocket URLs
	if !strings.Contains(contentType, "text/html") &&
		!strings.Contains(contentType, "text/javascript") &&
		!strings.Contains(contentType, "application/javascript") &&
		!strings.Contains(contentType, "application/x-javascript") {
		return nil
	}

	log.Printf("DEBUG: Rewriting response for %s (Content-Type: %s, Content-Encoding: %s)",
		resp.Request.URL.Path, contentType, resp.Header.Get("Content-Encoding"))

	// Get the hostname from the request
	hostname := resp.Request.Host

	// Check if we need to rewrite anything for this hostname
	// If not, skip the expensive body reading
	// (We can't check without reading, but we can at least log it)

	// Decompress if needed
	var reader io.ReadCloser = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Read the (possibly decompressed) response body
	body, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// Rewrite wss:// to ws:// and https:// to http:// in a single pass
	// This handles:
	// - Template literals: wss://${window.location.host}
	// - Literal URLs: wss://ubi-1.localhost:6189
	// - Protocol strings: "wss:" or 'wss:'
	// - HTTPS URLs for this hostname
	replacer := strings.NewReplacer(
		"wss://", "ws://",
		`"wss:"`, `"ws:"`,
		`'wss:'`, `'ws:'`,
		"https://"+hostname, "http://"+hostname,
	)
	modified := replacer.Replace(string(body))

	// Update response body with uncompressed content
	resp.Body = io.NopCloser(strings.NewReader(modified))
	resp.ContentLength = int64(len(modified))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(modified)))

	// Remove Content-Encoding since we're sending uncompressed
	resp.Header.Del("Content-Encoding")

	if len(modified) != len(body) {
		log.Printf("Rewrote protocol in %s response (%d -> %d bytes)", contentType, len(body), len(modified))
	} else {
		log.Printf("DEBUG: No changes needed for %s (hostname: %s)", resp.Request.URL.Path, hostname)
	}

	return nil
}

func (ps *Server) handleProxyError(w http.ResponseWriter, r *http.Request, err error) {
	log.Printf("Proxy error for %s: %v", r.URL, err)
	msg := "Bad Gateway"
	if strings.Contains(err.Error(), "certificate pinning") {
		msg = "Certificate Pinning Failed"
	} else if strings.Contains(err.Error(), "bastion set") {
		msg = "Bastion Connection Failed"
	}
	http.Error(w, fmt.Sprintf("%s: %v", msg, err), http.StatusBadGateway)
}

func (ps *Server) Close() {
	// Close all transports
	ps.transportMu.Lock()
	for _, transport := range ps.transports {
		transport.CloseIdleConnections()
	}
	ps.transportMu.Unlock()

	// Close all bastion connections
	ps.connMu.Lock()
	for _, conn := range ps.connections {
		conn.Close()
	}
	ps.connMu.Unlock()
}

// Helper functions

func calculateFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

func stripPort(hostPort string) string {
	if strings.HasPrefix(hostPort, "[") {
		if idx := strings.Index(hostPort, "]"); idx != -1 {
			return hostPort[1:idx]
		}
		return hostPort
	}
	if idx := strings.LastIndex(hostPort, ":"); idx != -1 {
		return hostPort[:idx]
	}
	return hostPort
}

func matchesWildcard(pattern, hostname string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:]
	return strings.HasSuffix(hostname, suffix) && hostname != suffix[1:]
}

func findUpstream(upstreams []Upstream, host string) *Upstream {
	host = stripPort(host)
	for i := range upstreams {
		if upstreams[i].Local == host {
			return &upstreams[i]
		}
	}
	for i := range upstreams {
		if matchesWildcard(upstreams[i].Local, host) {
			return &upstreams[i]
		}
	}
	return nil
}

func extractSubdomain(hostname, pattern string) string {
	if !strings.HasPrefix(pattern, "*.") {
		return ""
	}
	suffix := pattern[2:]
	if strings.HasSuffix(hostname, "."+suffix) {
		return hostname[:len(hostname)-len(suffix)-1]
	}
	return ""
}

func buildUpstreamURL(upstream *Upstream, hostname string) (string, error) {
	if !strings.Contains(upstream.Remote, "{subdomain}") {
		return upstream.Remote, nil
	}
	subdomain := extractSubdomain(hostname, upstream.Local)
	if subdomain == "" {
		return "", fmt.Errorf("could not extract subdomain from %s", hostname)
	}
	return strings.ReplaceAll(upstream.Remote, "{subdomain}", subdomain), nil
}

func verifyPinning(cert *x509.Certificate, pin string) error {
	// SHA256 is 32 bytes = 64 hex characters
	if len(pin) != 64 {
		return fmt.Errorf("invalid TLS fingerprint length (expected 64 hex chars, got %d)", len(pin))
	}
	if fingerprint := calculateFingerprint(cert); fingerprint != pin {
		return fmt.Errorf("certificate pinning failed: expected %s, got %s", pin, fingerprint)
	}
	return nil
}

func createTLSConfig(upstream *Upstream, hostname string) *tls.Config {
	return &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates provided")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}
			if err := verifyPinning(cert, upstream.Fingerprint); err != nil {
				return err
			}
			log.Printf("Certificate pinning verified for %s (sha256:%s)", hostname, calculateFingerprint(cert))
			return nil
		},
	}
}

// WebSocket support

func isWebSocketRequest(r *http.Request) bool {
	connection := strings.ToLower(r.Header.Get("Connection"))
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	return strings.Contains(connection, "upgrade") && upgrade == "websocket"
}

func (ps *Server) handleWebSocket(w http.ResponseWriter, r *http.Request, upstream *Upstream) {
	targetURL, err := buildUpstreamURL(upstream, r.Host)
	if err != nil {
		log.Printf("Error building upstream URL for WebSocket: %v", err)
		http.Error(w, "Invalid upstream configuration", http.StatusInternalServerError)
		return
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		log.Printf("Error parsing target URL: %v", err)
		http.Error(w, "Invalid target URL", http.StatusInternalServerError)
		return
	}

	// Ensure the host includes a port
	dialAddr := parsedURL.Host
	if !strings.Contains(dialAddr, ":") {
		if parsedURL.Scheme == "https" {
			dialAddr += ":443"
		} else {
			dialAddr += ":80"
		}
	}

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Error hijacking connection: %v", err)
		http.Error(w, "Failed to hijack connection", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Dial the upstream server
	var upstreamConn net.Conn
	if upstream.BastionSet != "" {
		conn, err := ps.getOrCreateConnection(upstream.BastionSet)
		if err != nil {
			log.Printf("Error getting bastion connection: %v", err)
			return
		}
		upstreamConn, err = conn.Dial(r.Context(), "tcp", dialAddr)
		if err != nil {
			log.Printf("Error dialing through bastion: %v", err)
			return
		}
	} else {
		upstreamConn, err = net.Dial("tcp", dialAddr)
		if err != nil {
			log.Printf("Error dialing upstream: %v", err)
			return
		}
	}
	defer upstreamConn.Close()

	// Wrap with TLS
	hostname := stripPort(parsedURL.Host)
	tlsConfig := createTLSConfig(upstream, hostname)
	tlsConn := tls.Client(upstreamConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}
	defer tlsConn.Close()

	// Manually write the HTTP upgrade request as raw text
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path += "?" + r.URL.RawQuery
	}

	log.Printf("WS: Sending upgrade request to %s with Host=%s, Origin=%s", parsedURL, hostname, parsedURL.Scheme+"://"+hostname)

	// Write request line
	fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(tlsConn, "Host: %s\r\n", hostname)
	fmt.Fprintf(tlsConn, "Upgrade: websocket\r\n")
	fmt.Fprintf(tlsConn, "Connection: Upgrade\r\n")
	fmt.Fprintf(tlsConn, "Sec-WebSocket-Version: %s\r\n", r.Header.Get("Sec-WebSocket-Version"))
	fmt.Fprintf(tlsConn, "Sec-WebSocket-Key: %s\r\n", r.Header.Get("Sec-WebSocket-Key"))

	if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		fmt.Fprintf(tlsConn, "Sec-WebSocket-Protocol: %s\r\n", proto)
	}
	if ext := r.Header.Get("Sec-WebSocket-Extensions"); ext != "" {
		fmt.Fprintf(tlsConn, "Sec-WebSocket-Extensions: %s\r\n", ext)
	}

	fmt.Fprintf(tlsConn, "Origin: %s://%s\r\n", parsedURL.Scheme, hostname)

	if cookie := r.Header.Get("Cookie"); cookie != "" {
		fmt.Fprintf(tlsConn, "Cookie: %s\r\n", cookie)
	}

	// End headers
	fmt.Fprintf(tlsConn, "\r\n")

	// Read the upgrade response
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), r)
	if err != nil {
		log.Printf("WS ERROR: Reading upgrade response: %v", err)
		return
	}
	log.Printf("WS: Received response: %d %s", resp.StatusCode, resp.Status)

	// Forward the response to the client
	if err := resp.Write(clientConn); err != nil {
		log.Printf("Error writing response to client: %v", err)
		return
	}

	// If upgrade successful, start bidirectional copy
	if resp.StatusCode == http.StatusSwitchingProtocols {
		log.Printf("WebSocket connection established for %s -> %s", r.Host, targetURL)
		done := make(chan struct{}, 2)

		go func() {
			io.Copy(tlsConn, clientConn)
			done <- struct{}{}
		}()

		go func() {
			io.Copy(clientConn, tlsConn)
			done <- struct{}{}
		}()

		<-done
		log.Printf("WebSocket connection closed for %s", r.Host)
	}
}
