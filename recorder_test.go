package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// clientFrame frames payload as a browser does: masked.
func clientFrame(opcode byte, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x80 | opcode)
	switch n := len(payload); {
	case n < 126:
		b.WriteByte(0x80 | byte(n))
	case n < 1<<16:
		b.WriteByte(0x80 | 126)
		binary.Write(&b, binary.BigEndian, uint16(n))
	default:
		b.WriteByte(0x80 | 127)
		binary.Write(&b, binary.BigEndian, uint64(n))
	}
	key := []byte{0x12, 0x34, 0x56, 0x78}
	b.Write(key)
	for i, c := range payload {
		b.WriteByte(c ^ key[i%4])
	}
	return b.Bytes()
}

// serverFrame frames payload as a server does: unmasked.
func serverFrame(opcode byte, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteByte(0x80 | opcode)
	if len(payload) < 126 {
		b.WriteByte(byte(len(payload)))
	} else {
		b.WriteByte(126)
		binary.Write(&b, binary.BigEndian, uint16(len(payload)))
	}
	b.Write(payload)
	return b.Bytes()
}

// readFrame reads one frame from r, as the fake BMC and the browser need.
func readFrame(r *bufio.Reader) (*frame, error) {
	var buf []byte
	for {
		f, _, err := parseFrame(buf)
		if f != nil || err != nil {
			return f, err
		}
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		buf = append(buf, c)
	}
}

func TestReadFrame(t *testing.T) {
	long := bytes.Repeat([]byte{0xab}, 300)
	stream := append(clientFrame(2, long), serverFrame(1, []byte("hi"))...)
	stream = append(stream, 0x00, 0x7f) // a frame claiming 2^64-ish bytes
	stream = append(stream, bytes.Repeat([]byte{0xff}, 8)...)
	r := bufio.NewReader(bytes.NewReader(stream))

	f, err := readFrame(r)
	if err != nil || !f.fin || f.opcode != 2 || !f.masked || !bytes.Equal(f.payload, long) {
		t.Fatalf("masked binary frame: %+v, %v", f, err)
	}
	f, err = readFrame(r)
	if err != nil || f.opcode != 1 || f.masked || string(f.payload) != "hi" {
		t.Fatalf("unmasked text frame: %+v, %v", f, err)
	}
	if _, err = readFrame(r); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("oversized frame: %v", err)
	}
}

func TestRecorderMasks(t *testing.T) {
	rec, err := NewRecorder(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()

	h := rec.headers(http.Header{
		"Cookie":        {"QSESSIONID=abc; lang=en"},
		"Set-Cookie":    {"QSESSIONID=abc; Path=/; HttpOnly"},
		"Authorization": {"Basic YWRtaW46aHVudGVyMg=="},
		"X-Csrftoken":   {"tok"},
		"Accept":        {"*/*"},
	})
	same := rec.mask("abc")
	if got := h["Cookie"][0]; got != "QSESSIONID="+same+"; lang="+rec.mask("en") {
		t.Errorf("Cookie: %s", got)
	}
	if got := h["Set-Cookie"][0]; got != "QSESSIONID="+same+"; Path=/; HttpOnly" {
		t.Errorf("Set-Cookie: %s", got)
	}
	for _, k := range []string{"Authorization", "X-Csrftoken"} {
		if !strings.HasPrefix(h[k][0], "<<masked:") {
			t.Errorf("%s not masked: %s", k, h[k][0])
		}
	}
	if h["Accept"][0] != "*/*" {
		t.Errorf("Accept masked: %s", h["Accept"][0])
	}

	body := string(rec.body([]byte(`{"UserName":"admin","Password":"hunter2","Oem":{"Token":7,"Port":443}}`), ""))
	if strings.Contains(body, "hunter2") || strings.Contains(body, `"Token":7`) || !strings.Contains(body, `"admin"`) || !strings.Contains(body, "443") {
		t.Errorf("JSON body: %s", body)
	}
	form := string(rec.body([]byte("username=admin&password=hunter2"), "application/x-www-form-urlencoded"))
	if strings.Contains(form, "hunter2") || !strings.Contains(form, "username=admin") {
		t.Errorf("form body: %s", form)
	}
}

// vmToken is the session token the fake BMC's login gives, which the
// browser then sends inside WebSocket frames, as a BMC's virtual media
// has it do.
const vmToken = "s3cr3t-vm-token-4f9a2c"

// authPacket is the binary frame that carries the token: a 10-byte
// header, 0x01, then the token zero-padded to 64 bytes. It is valid
// UTF-8, so it is recorded as text.
func authPacket() []byte {
	b := append([]byte("VMHDR\x00\x00\x00\x4b\x00"), 0x01)
	return append(b, append([]byte(vmToken), make([]byte, 64-len(vmToken))...)...)
}

// fakeBMC answers a login with a token and cookies, and echoes every
// frame of a WebSocket at /vm, after noting what its upgrade asked for.
type fakeBMC struct {
	mu         sync.Mutex
	extensions string
}

func (b *fakeBMC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/session":
		io.ReadAll(r.Body)
		http.SetCookie(w, &http.Cookie{Name: "QSESSIONID", Value: "s3cr3t-session", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "SESSION", Value: vmToken, Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":0,"CSRFToken":"s3cr3t-csrf"}`)
	case "/vm":
		b.mu.Lock()
		b.extensions = r.Header.Get("Sec-WebSocket-Extensions")
		b.mu.Unlock()
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		conn, rw, _ := w.(http.Hijacker).Hijack()
		defer conn.Close()
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
		rw.Flush()
		for {
			f, err := readFrame(rw.Reader)
			if err != nil {
				return
			}
			conn.Write(serverFrame(f.opcode, f.payload))
		}
	default:
		http.NotFound(w, r)
	}
}

func readEvents(t *testing.T, dir string) []map[string]any {
	raw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var evs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		evs = append(evs, ev)
	}
	return evs
}

// TestRecordSession drives a login and a WebSocket through the proxy to
// a fake BMC, then holds the recording to what passed: every frame both
// ways, unmasked and in order, no secret in any file, and no extension
// asked of the upstream. The login's token, masked in the upgrade's
// cookie, is scrubbed from the binary and the text frame that carry it
// too, the binary frame keeping its length.
func TestRecordSession(t *testing.T) {
	bmc := &fakeBMC{}
	srv := newTestHTTPSServer(t, bmc)
	defer srv.Close()

	dir := t.TempDir()
	cfg := &Config{Upstreams: []Upstream{{Local: "bmc", Remote: srv.url, Fingerprint: srv.Fingerprint()}}}
	port, ps := startProxy(t, cfg, nil)
	rec, err := NewRecorder(dir)
	if err != nil {
		t.Fatal(err)
	}
	ps.rec = rec

	// The login.
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/api/session", port),
		strings.NewReader("username=admin&password=hunter2"))
	req.Host = "bmc"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// The WebSocket, as a browser opens it.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "GET /vm HTTP/1.1\r\nHost: bmc\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Extensions: permessage-deflate\r\nCookie: QSESSIONID=s3cr3t-session; SESSION="+vmToken+"\r\n"+
		"X-CSRFTOKEN: s3cr3t-csrf\r\n\r\n")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("upgrade: %q", status)
	}
	for line, _ := br.ReadString('\n'); line != "\r\n"; line, _ = br.ReadString('\n') {
	}

	nbd := append([]byte("NBDMAGIC"), bytes.Repeat([]byte{0, 1, 2, 3}, 300)...)
	sent := []struct {
		opcode  byte
		payload []byte
	}{{2, nbd}, {1, []byte(`{"cmd":"mount","token":"s3cr3t-csrf"}`)}, {2, authPacket()}, {1, []byte("AUTH " + vmToken)}}
	for _, s := range sent {
		conn.Write(clientFrame(s.opcode, s.payload))
		f, err := readFrame(br)
		if err != nil || !bytes.Equal(f.payload, s.payload) {
			t.Fatalf("echo of opcode %d: %v", s.opcode, err)
		}
	}
	conn.Close()

	// The frames are parsed beside the stream: wait for the last of them,
	// and for the close.
	var evs []map[string]any
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		evs = readEvents(t, dir)
		n, closed := 0, false
		for _, ev := range evs {
			n += map[bool]int{true: 1}[ev["kind"] == "ws"]
			closed = closed || ev["kind"] == "ws-close"
		}
		if n == 2*len(sent) && closed || time.Now().After(deadline) {
			break
		}
	}

	var kinds []string
	var frames []string
	tokenMask := rec.mask(vmToken)
	for _, ev := range evs {
		kinds = append(kinds, ev["kind"].(string))
		if ev["kind"] == "ws" {
			p := ev["payload"].(map[string]any)
			frames = append(frames, fmt.Sprintf("%s %v %v", ev["dir"], ev["opcode"], p["len"]))
			if text, _ := p["text"].(string); strings.HasPrefix(text, "VMHDR") || strings.HasPrefix(text, "AUTH") {
				if len(text) != int(p["len"].(float64)) {
					t.Errorf("%s frame recorded as %d bytes, not %v", ev["dir"], len(text), p["len"])
				}
				if masks := fmt.Sprint(p["masks"]); masks != "["+tokenMask+"]" {
					t.Errorf("%s frame %q notes masks %s, want [%s]", ev["dir"], text, masks, tokenMask)
				}
			}
			if blob, ok := p["blob"].(string); ok {
				b, _ := os.ReadFile(filepath.Join(dir, "blobs", blob))
				if !bytes.Equal(b, nbd) {
					t.Errorf("blob %s is not the binary frame's payload", blob)
				}
			}
		}
	}
	// A text frame is masked and written again, so its length is the masked one's.
	text := len(rec.body(sent[1].payload, ""))
	auth := len("AUTH " + vmToken)
	if got, want := strings.Join(frames, ", "), fmt.Sprintf("up 2 1208, down 2 1208, up 1 %d, down 1 %d, up 2 75, down 2 75, up 1 %d, down 1 %d",
		text, text, auth, auth); got != want {
		t.Errorf("frames: %s, want %s", got, want)
	}
	for _, want := range []string{"start", "http", "ws-open", "ws-close"} {
		if !strings.Contains(strings.Join(kinds, " "), want) {
			t.Errorf("no %s event in %v", want, kinds)
		}
	}

	bmc.mu.Lock()
	if bmc.extensions != "" {
		t.Errorf("the upstream was asked for %q", bmc.extensions)
	}
	bmc.mu.Unlock()

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, _ := os.ReadFile(path)
		for _, secret := range []string{"hunter2", "s3cr3t"} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("%s holds %s", path, secret)
			}
		}
		return nil
	})
}
