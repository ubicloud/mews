// Package mux: stream mux over one bidi byte-stream, client-only.
//
// Wire: type:u8 flags:u8 stream:u32 length:u16 payload
// Types: 0=SYN(payload=destination) 1=DATA 2=WIN(u32 credit)
// Flags: 1=FIN (DATA only). Receiver consumes N bytes -> sends WIN of N.
//
// Client-only: this peer initiates streams; inbound SYNs are dropped.
package mux

import (
	"encoding/binary"
	"io"
	"sync"
)

const (
	tSYN, tDATA, tWIN = 0, 1, 2
	fFIN              = 1
	maxFrame          = 32 * 1024
	initialWindow     = 256 * 1024
)

type Mux struct {
	r       io.Reader
	w       io.Writer
	wmu     sync.Mutex
	smu     sync.Mutex
	streams map[uint32]*Stream
	nid     uint32
}

func NewRW(r io.Reader, w io.Writer) *Mux {
	m := &Mux{r: r, w: w, streams: map[uint32]*Stream{}, nid: 1}
	go m.readLoop()
	return m
}

// Open initiates a stream and sends payload in the SYN. Returns
// io.ErrClosedPipe if the mux has been Closed -- this can race a reconnect
// in mews's muxerDialer.
func (m *Mux) Open(payload []byte) (*Stream, error) {
	m.smu.Lock()
	if m.streams == nil {
		m.smu.Unlock()
		return nil, io.ErrClosedPipe
	}
	id := m.nid
	m.nid += 2
	s := newStream(m, id)
	m.streams[id] = s
	m.smu.Unlock()
	return s, m.frame(tSYN, 0, id, payload)
}

func (m *Mux) Close() error {
	m.smu.Lock()
	streams := m.streams
	m.streams = nil
	m.smu.Unlock()
	for _, s := range streams {
		s.mu.Lock()
		s.dead = true
		s.cond.Broadcast()
		s.mu.Unlock()
	}
	return nil
}

func (m *Mux) frame(t, fl uint8, id uint32, payload []byte) error {
	buf := make([]byte, 8+len(payload))
	buf[0], buf[1] = t, fl
	binary.BigEndian.PutUint32(buf[2:6], id)
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(payload)))
	copy(buf[8:], payload)
	m.wmu.Lock()
	defer m.wmu.Unlock()
	_, err := m.w.Write(buf)
	return err
}

func (m *Mux) readLoop() {
	defer m.Close()
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(m.r, hdr); err != nil {
			return
		}
		t, fl := hdr[0], hdr[1]
		id := binary.BigEndian.Uint32(hdr[2:6])
		ln := binary.BigEndian.Uint16(hdr[6:8])
		p := make([]byte, ln)
		if _, err := io.ReadFull(m.r, p); err != nil {
			return
		}
		m.smu.Lock()
		s := m.streams[id]
		m.smu.Unlock()
		// s may be nil if Mux.Close races inbound frames: streams gets
		// nil'd, then a DATA/WIN frame already on the wire arrives.
		if s == nil {
			continue
		}
		switch t {
		case tDATA:
			s.deliver(p)
			if fl&fFIN != 0 {
				s.deliverEOF()
			}
		case tWIN:
			s.grant(int64(binary.BigEndian.Uint32(p)))
		}
	}
}

type Stream struct {
	mux    *Mux
	id     uint32
	mu     sync.Mutex
	cond   *sync.Cond
	rcv    []byte
	rcvEOF bool
	dead   bool
	swin   int64
}

func newStream(m *Mux, id uint32) *Stream {
	s := &Stream{mux: m, id: id, swin: initialWindow}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	for len(s.rcv) == 0 && !s.rcvEOF && !s.dead {
		s.cond.Wait()
	}
	if len(s.rcv) == 0 {
		s.mu.Unlock()
		return 0, io.EOF
	}
	n := copy(p, s.rcv)
	s.rcv = s.rcv[n:]
	s.mu.Unlock()
	var d [4]byte
	binary.BigEndian.PutUint32(d[:], uint32(n))
	_ = s.mux.frame(tWIN, 0, s.id, d[:])
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	total := 0
	for total < len(p) {
		s.mu.Lock()
		for s.swin <= 0 && !s.dead {
			s.cond.Wait()
		}
		if s.dead {
			s.mu.Unlock()
			return total, io.ErrClosedPipe
		}
		k := int64(len(p) - total)
		if k > s.swin {
			k = s.swin
		}
		if k > maxFrame {
			k = maxFrame
		}
		s.swin -= k
		s.mu.Unlock()
		if err := s.mux.frame(tDATA, 0, s.id, p[total:total+int(k)]); err != nil {
			return total, err
		}
		total += int(k)
	}
	return total, nil
}

func (s *Stream) CloseWrite() error { return s.mux.frame(tDATA, fFIN, s.id, nil) }

func (s *Stream) deliver(p []byte) {
	s.mu.Lock()
	s.rcv = append(s.rcv, p...)
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) deliverEOF() {
	s.mu.Lock()
	s.rcvEOF = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) grant(d int64) {
	s.mu.Lock()
	s.swin += d
	s.cond.Broadcast()
	s.mu.Unlock()
}
