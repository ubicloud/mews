// Package mux: stream mux over one bidi byte-stream, client-only.
//
// Flags: 1=FIN (DATA only). Receiver consumes N bytes -> sends WIN of N.
// Wire: kind u8 flags u8 stream u32 length u16 payload
// Kinds: 0=OPEN(payload=destination) 1=DATA 2=WIN(u32 credit)
//
// Client-only: this peer initiates streams; inbound OPENs are dropped.
package mux

import (
	"encoding/binary"
	"io"
	"sync"
)

const (
	kindOPEN, kindDATA, kindWIN = 0, 1, 2
	flagFIN                     = 1
	maxFrame                    = 32 * 1024
	initialWindow               = 256 * 1024
)

type Mux struct {
	r         io.Reader
	w         io.Writer
	writeMu   sync.Mutex
	streamsMu sync.Mutex
	streams   map[uint32]*Stream
	nextID    uint32
}

func NewRW(r io.Reader, w io.Writer) *Mux {
	m := &Mux{r: r, w: w, streams: map[uint32]*Stream{}, nextID: 1}
	go m.readLoop()
	return m
}

// Open initiates a stream; the OPEN frame carries the destination payload.
// Returns io.ErrClosedPipe if the mux is Closed (races a muxerDialer reconnect).
func (m *Mux) Open(payload []byte) (*Stream, error) {
	m.streamsMu.Lock()
	if m.streams == nil {
		m.streamsMu.Unlock()
		return nil, io.ErrClosedPipe
	}
	id := m.nextID
	m.nextID++
	s := newStream(m, id)
	m.streams[id] = s
	m.streamsMu.Unlock()
	return s, m.frame(kindOPEN, 0, id, payload)
}

// Close nils the stream table and wakes every stream's blocked Read/Write.
func (m *Mux) Close() error {
	m.streamsMu.Lock()
	streams := m.streams
	m.streams = nil
	m.streamsMu.Unlock()
	for _, s := range streams {
		s.mu.Lock()
		s.dead = true
		s.cond.Broadcast()
		s.mu.Unlock()
	}
	return nil
}

// frame writes one header+payload under writeMu so concurrent senders interleave.
func (m *Mux) frame(kind, flags uint8, id uint32, payload []byte) error {
	buf := make([]byte, 8+len(payload))
	buf[0], buf[1] = kind, flags
	binary.BigEndian.PutUint32(buf[2:6], id)
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(payload)))
	copy(buf[8:], payload)
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	_, err := m.w.Write(buf)
	return err
}

// readLoop demuxes inbound frames to streams until the transport errors.
func (m *Mux) readLoop() {
	defer m.Close()
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(m.r, hdr); err != nil {
			return
		}
		kind, flags := hdr[0], hdr[1]
		id := binary.BigEndian.Uint32(hdr[2:6])
		n := binary.BigEndian.Uint16(hdr[6:8])
		p := make([]byte, n)
		if _, err := io.ReadFull(m.r, p); err != nil {
			return
		}
		m.streamsMu.Lock()
		s := m.streams[id]
		m.streamsMu.Unlock()
		// nil if Close raced this frame: table got nil'd, frame was already on the wire.
		if s == nil {
			continue
		}
		switch kind {
		case kindDATA:
			s.deliver(p)
			if flags&flagFIN != 0 {
				s.deliverEOF()
			}
		case kindWIN:
			s.grant(int64(binary.BigEndian.Uint32(p)))
		}
	}
}

type Stream struct {
	mux        *Mux
	id         uint32
	mu         sync.Mutex
	cond       *sync.Cond
	recvBuf    []byte
	recvEOF    bool
	dead       bool
	sendWindow int64
}

func newStream(m *Mux, id uint32) *Stream {
	s := &Stream{mux: m, id: id, sendWindow: initialWindow}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Read returns buffered bytes and credits the peer for what it took.
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	for len(s.recvBuf) == 0 && !s.recvEOF && !s.dead {
		s.cond.Wait()
	}
	if len(s.recvBuf) == 0 {
		s.mu.Unlock()
		return 0, io.EOF
	}
	n := copy(p, s.recvBuf)
	s.recvBuf = s.recvBuf[n:]
	s.mu.Unlock()
	var d [4]byte
	binary.BigEndian.PutUint32(d[:], uint32(n))
	_ = s.mux.frame(kindWIN, 0, s.id, d[:])
	return n, nil
}

// Write sends p as DATA frames, blocking on the send window.
func (s *Stream) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		s.mu.Lock()
		// Block until the peer grants window or the stream dies.
		for s.sendWindow <= 0 && !s.dead {
			s.cond.Wait()
		}
		if s.dead {
			s.mu.Unlock()
			return total, io.ErrClosedPipe
		}
		k := int64(len(p) - total)
		if k > s.sendWindow {
			k = s.sendWindow
		}
		if k > maxFrame {
			k = maxFrame
		}
		s.sendWindow -= k
		s.mu.Unlock()
		if err := s.mux.frame(kindDATA, 0, s.id, p[total:total+int(k)]); err != nil {
			return total, err
		}
		total += int(k)
	}
	return total, nil
}

// CloseWrite half-closes: FIN the peer but keep reading.
func (s *Stream) CloseWrite() error { return s.mux.frame(kindDATA, flagFIN, s.id, nil) }

// Close FINs the peer, wakes any Read/Write, and drops the stream from the
// table. CloseWrite alone leaves an io.Copy partner stuck on Read.
func (s *Stream) Close() error {
	err := s.mux.frame(kindDATA, flagFIN, s.id, nil)
	s.mu.Lock()
	s.dead = true
	s.cond.Broadcast()
	s.mu.Unlock()
	s.mux.streamsMu.Lock()
	delete(s.mux.streams, s.id)
	s.mux.streamsMu.Unlock()
	return err
}

// deliver appends inbound DATA and wakes a blocked Read.
func (s *Stream) deliver(p []byte) {
	s.mu.Lock()
	s.recvBuf = append(s.recvBuf, p...)
	s.cond.Broadcast()
	s.mu.Unlock()
}

// deliverEOF marks the read side done (peer sent FIN).
func (s *Stream) deliverEOF() {
	s.mu.Lock()
	s.recvEOF = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// grant adds peer-issued send credit and wakes a blocked Write.
func (s *Stream) grant(d int64) {
	s.mu.Lock()
	s.sendWindow += d
	s.cond.Broadcast()
	s.mu.Unlock()
}
