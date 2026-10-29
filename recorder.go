package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Recorder writes what passes through the proxy into a directory, so that
// a session with a BMC's web interface can be studied afterwards and
// replayed in tests: each HTTP exchange and each WebSocket frame becomes
// one JSON line of events.jsonl, and a body or payload longer than
// inlineMax goes to blobs/<sha256> instead.
//
// Secrets are masked before anything is written: credential headers,
// cookie values, and the values of JSON, form and query fields whose
// names look like a password, token or session. A masked value becomes
// <<masked:H>>, where H is an HMAC under a key made for this recording
// alone, so one token can be followed through a recording without
// being revealed. Binary WebSocket payloads are written as they are.
type Recorder struct {
	dir   string
	key   []byte
	start time.Time

	mu  sync.Mutex
	out *os.File
	enc *json.Encoder
	ws  int
}

const inlineMax = 512

// sensitiveName matches the names of headers and fields whose values are
// masked.
var sensitiveName = regexp.MustCompile(`(?i)pass|token|secret|csrf|xsrf|session|cookie|auth`)

func NewRecorder(dir string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return nil, err
	}
	out, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		out.Close()
		return nil, err
	}
	rec := &Recorder{dir: dir, key: key, start: time.Now(), out: out, enc: json.NewEncoder(out)}
	rec.enc.SetEscapeHTML(false)
	rec.write(map[string]any{"kind": "start", "time": rec.start.UTC().Format(time.RFC3339Nano), "format": 1})
	return rec, nil
}

func (rec *Recorder) Close() error {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return rec.out.Close()
}

// write adds one event, stamped with the seconds since the recording
// began.
func (rec *Recorder) write(ev map[string]any) {
	ev["t"] = time.Since(rec.start).Seconds()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if err := rec.enc.Encode(ev); err != nil {
		fmt.Fprintf(os.Stderr, "record: %v\n", err)
	}
}

func (rec *Recorder) mask(v string) string {
	m := hmac.New(sha256.New, rec.key)
	m.Write([]byte(v))
	return "<<masked:" + hex.EncodeToString(m.Sum(nil))[:12] + ">>"
}

// headers returns h with the values of credential headers masked. A
// cookie keeps its name and loses its value, and a Set-Cookie keeps its
// attributes.
func (rec *Recorder) headers(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for name, vals := range h {
		lower := strings.ToLower(name)
		for _, v := range vals {
			switch {
			case lower == "cookie":
				parts := strings.Split(v, ";")
				for i, p := range parts {
					if k, val, ok := strings.Cut(p, "="); ok {
						parts[i] = k + "=" + rec.mask(val)
					}
				}
				v = strings.Join(parts, ";")
			case lower == "set-cookie":
				first, attrs, _ := strings.Cut(v, ";")
				if k, val, ok := strings.Cut(first, "="); ok {
					first = k + "=" + rec.mask(val)
				}
				if attrs != "" {
					first += ";" + attrs
				}
				v = first
			case lower == "sec-websocket-key" || lower == "sec-websocket-accept":
			case sensitiveName.MatchString(lower):
				v = rec.mask(v)
			}
			out[name] = append(out[name], v)
		}
	}
	return out
}

// target returns a request's path and query, the query's sensitive values
// masked.
func (rec *Recorder) target(u *url.URL) string {
	if u.RawQuery == "" {
		return u.Path
	}
	return u.Path + "?" + rec.form(u.RawQuery)
}

func (rec *Recorder) form(raw string) string {
	q, err := url.ParseQuery(raw)
	if err != nil {
		return rec.mask(raw)
	}
	for k, vals := range q {
		if sensitiveName.MatchString(k) {
			for i, v := range vals {
				vals[i] = rec.mask(v)
			}
		}
	}
	return q.Encode()
}

// json masks the scalar values under sensitive names anywhere in v.
func (rec *Recorder) json(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			switch val.(type) {
			case map[string]any, []any:
				x[k] = rec.json(val)
			default:
				if val != nil && sensitiveName.MatchString(k) {
					x[k] = rec.mask(fmt.Sprint(val))
				}
			}
		}
	case []any:
		for i, val := range x {
			x[i] = rec.json(val)
		}
	}
	return v
}

// body masks b by its content type, or by its look where the type says
// nothing: JSON and forms field by field. A JSON body is written again
// after masking, so its spacing and key order may differ from the
// original's.
func (rec *Recorder) body(b []byte, contentType string) []byte {
	trimmed := bytes.TrimSpace(b)
	if strings.Contains(contentType, "json") || (len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')) {
		var v any
		if json.Unmarshal(trimmed, &v) == nil {
			var out bytes.Buffer
			enc := json.NewEncoder(&out)
			enc.SetEscapeHTML(false)
			if enc.Encode(rec.json(v)) == nil {
				return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
			}
		}
	}
	if strings.Contains(contentType, "x-www-form-urlencoded") {
		return []byte(rec.form(string(b)))
	}
	return b
}

// payload describes b for an event: inline as text or base64 if short,
// else by the name of the blob it is kept in.
func (rec *Recorder) payload(b []byte) map[string]any {
	p := map[string]any{"len": len(b)}
	if len(b) == 0 {
		return p
	}
	if len(b) > inlineMax {
		sum := sha256.Sum256(b)
		name := hex.EncodeToString(sum[:])
		path := filepath.Join(rec.dir, "blobs", name)
		if _, err := os.Stat(path); err != nil {
			if err := os.WriteFile(path, b, 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "record: %v\n", err)
			}
		}
		p["blob"] = name
	} else if utf8.Valid(b) {
		p["text"] = string(b)
	} else {
		p["b64"] = base64.StdEncoding.EncodeToString(b)
	}
	return p
}

// HTTP records one exchange as the browser saw it: the response after
// mews's own rewriting.
func (rec *Recorder) HTTP(r *http.Request, reqBody []byte, status int, respHeader http.Header, respBody []byte) {
	rec.write(map[string]any{
		"kind": "http", "method": r.Method, "host": r.Host, "target": rec.target(r.URL),
		"req_headers": rec.headers(r.Header), "req_body": rec.payload(rec.body(reqBody, r.Header.Get("Content-Type"))),
		"status": status, "resp_headers": rec.headers(respHeader),
		"resp_body": rec.payload(rec.body(respBody, respHeader.Get("Content-Type"))),
	})
}

// WebSocket records an upgrade and returns the number its frames carry.
// Headers are the browser's, as it sent them, before mews dropped any.
func (rec *Recorder) WebSocket(r *http.Request, status int, respHeader http.Header) int {
	rec.mu.Lock()
	rec.ws++
	n := rec.ws
	rec.mu.Unlock()
	rec.write(map[string]any{
		"kind": "ws-open", "ws": n, "host": r.Host, "target": rec.target(r.URL),
		"req_headers": rec.headers(r.Header), "status": status, "resp_headers": rec.headers(respHeader),
	})
	return n
}

// Frames returns a writer to tee one direction of WebSocket n into, "up"
// from the browser or "down" from the upstream. Each frame is parsed and
// recorded within the Write that completes it, before the copy forwards
// those bytes, so the events of the two directions are in the order the
// frames crossed mews. The writer never fails, so recording cannot stall
// or break the stream: past bytes it cannot parse as a frame, it records
// the error and keeps nothing more.
func (rec *Recorder) Frames(n int, dir string) io.Writer {
	return &frameTee{rec: rec, ws: n, dir: dir}
}

// WebSocketClosed records that WebSocket n ended, and which side ended it.
func (rec *Recorder) WebSocketClosed(n int, by string) {
	rec.write(map[string]any{"kind": "ws-close", "ws": n, "by": by})
}

type frameTee struct {
	rec    *Recorder
	ws     int
	dir    string
	buf    []byte
	broken bool
}

func (t *frameTee) Write(b []byte) (int, error) {
	if t.broken {
		return len(b), nil
	}
	t.buf = append(t.buf, b...)
	for {
		f, used, err := parseFrame(t.buf)
		if err != nil {
			t.rec.write(map[string]any{"kind": "ws-error", "ws": t.ws, "dir": t.dir, "error": err.Error()})
			t.broken, t.buf = true, nil
			return len(b), nil
		}
		if f == nil {
			return len(b), nil
		}
		t.buf = t.buf[used:]
		p := f.payload
		if f.opcode == 1 {
			p = t.rec.body(p, "")
		}
		t.rec.write(map[string]any{"kind": "ws", "ws": t.ws, "dir": t.dir, "fin": f.fin, "rsv": f.rsv,
			"opcode": f.opcode, "masked": f.masked, "payload": t.rec.payload(p)})
	}
}

type frame struct {
	fin     bool
	rsv     byte
	opcode  byte
	masked  bool
	payload []byte
}

// maxFrame bounds the payload one frame may claim, so a stream that is
// not WebSocket framing after all cannot make the parser hold without
// limit.
const maxFrame = 64 << 20

// parseFrame parses the RFC 6455 frame at the head of b and unmasks its
// payload, returning the frame and the bytes it took, or no frame while
// b holds only part of one.
func parseFrame(b []byte) (*frame, int, error) {
	if len(b) < 2 {
		return nil, 0, nil
	}
	f := &frame{fin: b[0]&0x80 != 0, rsv: b[0] >> 4 & 7, opcode: b[0] & 0x0f, masked: b[1]&0x80 != 0}
	n, at := uint64(b[1]&0x7f), 2
	switch n {
	case 126:
		if len(b) < 4 {
			return nil, 0, nil
		}
		n, at = uint64(binary.BigEndian.Uint16(b[2:4])), 4
	case 127:
		if len(b) < 10 {
			return nil, 0, nil
		}
		n, at = binary.BigEndian.Uint64(b[2:10]), 10
	}
	if n > maxFrame {
		return nil, 0, fmt.Errorf("frame of %d bytes, more than %d", n, maxFrame)
	}
	var key []byte
	if f.masked {
		if len(b) < at+4 {
			return nil, 0, nil
		}
		key, at = b[at:at+4], at+4
	}
	end := at + int(n)
	if len(b) < end {
		return nil, 0, nil
	}
	f.payload = append([]byte(nil), b[at:end]...)
	for i := range key {
		for j := i; j < len(f.payload); j += 4 {
			f.payload[j] ^= key[i]
		}
	}
	return f, end, nil
}

// recordingWriter keeps a copy of a response as it is written to the
// browser.
type recordingWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *recordingWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *recordingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
