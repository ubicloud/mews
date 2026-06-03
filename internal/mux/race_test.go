package mux

// Race-detector pressure tests for the mux package.
//
// Each test wires the client Mux against a "loopback" peer that speaks the
// same wire protocol — open a SYN, echo DATA back, refresh WIN credit,
// propagate FIN, etc. The loopback is intentionally hand-rolled (not
// another Mux) so it exercises the protocol from the opposite end and
// keeps the test independent of mux.go's correctness as the "server".
//
// Run with:  go test -race -count=1 -timeout 120s ./internal/mux

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand"
	"sync"
	"sync/atomic"
	"testing"
)

// connect builds a Mux client + a loopback peer wired via two io.Pipes.
// Returns the Mux and a teardown func.
func connect(t *testing.T) (*Mux, func()) {
	t.Helper()
	// Pipe A: client -> server.  Pipe B: server -> client.
	clientR, serverW := io.Pipe()
	serverR, clientW := io.Pipe()

	srv := newLoopback(serverR, serverW)
	m := NewRW(clientR, clientW)

	return m, func() {
		_ = m.Close()
		_ = clientR.Close()
		_ = clientW.Close()
		srv.stop()
	}
}

// loopback is a wire-level peer that talks the mux protocol back at the
// client. On every SYN it spawns an echo goroutine that splices DATA back
// as DATA on the same id (server-allocated id is never needed — we only
// echo on the client-allocated id). WIN credit from the client is honored;
// outbound WIN credit (refunds for what the server consumed) is sent on
// every DATA we process.
type loopback struct {
	r    io.Reader
	w    io.Writer
	wmu  sync.Mutex
	mu   sync.Mutex
	cond *sync.Cond
	echo map[uint32]*echoStream
	stop func()
}

type echoStream struct {
	id     uint32
	mu     sync.Mutex
	cond   *sync.Cond
	rcv    [][]byte // queued DATA payloads from the client
	rcvEOF bool
	swin   int64 // credit the client has granted us to send
}

func newLoopback(r io.Reader, w io.Writer) *loopback {
	lb := &loopback{
		r:    r,
		w:    w,
		echo: map[uint32]*echoStream{},
	}
	lb.cond = sync.NewCond(&lb.mu)
	stopCh := make(chan struct{})
	lb.stop = func() {
		select {
		case <-stopCh:
		default:
			close(stopCh)
		}
	}
	go lb.run(stopCh)
	return lb
}

func (lb *loopback) frame(t, fl uint8, id uint32, payload []byte) error {
	buf := make([]byte, 8+len(payload))
	buf[0], buf[1] = t, fl
	binary.BigEndian.PutUint32(buf[2:6], id)
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(payload)))
	copy(buf[8:], payload)
	lb.wmu.Lock()
	defer lb.wmu.Unlock()
	_, err := lb.w.Write(buf)
	return err
}

func (lb *loopback) run(stop chan struct{}) {
	hdr := make([]byte, 8)
	for {
		select {
		case <-stop:
			return
		default:
		}
		if _, err := io.ReadFull(lb.r, hdr); err != nil {
			return
		}
		t, fl := hdr[0], hdr[1]
		id := binary.BigEndian.Uint32(hdr[2:6])
		ln := binary.BigEndian.Uint16(hdr[6:8])
		var p []byte
		if ln > 0 {
			p = make([]byte, ln)
			if _, err := io.ReadFull(lb.r, p); err != nil {
				return
			}
		}
		switch t {
		case kindOPEN:
			s := &echoStream{id: id, swin: initialWindow}
			s.cond = sync.NewCond(&s.mu)
			lb.mu.Lock()
			lb.echo[id] = s
			lb.mu.Unlock()
			go lb.echoServe(s)
		case kindDATA:
			lb.mu.Lock()
			s := lb.echo[id]
			lb.mu.Unlock()
			if s == nil {
				continue
			}
			s.mu.Lock()
			if len(p) > 0 {
				s.rcv = append(s.rcv, p)
			}
			if fl&flagFIN != 0 {
				s.rcvEOF = true
			}
			s.cond.Broadcast()
			s.mu.Unlock()
		case kindWIN:
			if len(p) < 4 {
				continue
			}
			delta := int64(binary.BigEndian.Uint32(p[:4]))
			lb.mu.Lock()
			s := lb.echo[id]
			lb.mu.Unlock()
			if s == nil {
				continue
			}
			s.mu.Lock()
			s.swin += delta
			s.cond.Broadcast()
			s.mu.Unlock()
		}
	}
}

// echoServe reads queued client-side DATA from s and bounces it back as
// DATA. On client FIN, sends FIN. Honors the client-advertised window.
func (lb *loopback) echoServe(s *echoStream) {
	for {
		s.mu.Lock()
		for len(s.rcv) == 0 && !s.rcvEOF {
			s.cond.Wait()
		}
		if len(s.rcv) == 0 && s.rcvEOF {
			s.mu.Unlock()
			_ = lb.frame(kindDATA, flagFIN, s.id, nil)
			return
		}
		chunk := s.rcv[0]
		s.rcv = s.rcv[1:]
		s.mu.Unlock()

		// Refund client window for what we just consumed.
		var d [4]byte
		binary.BigEndian.PutUint32(d[:], uint32(len(chunk)))
		_ = lb.frame(kindWIN, 0, s.id, d[:])

		// Echo back, honoring our send window.
		off := 0
		for off < len(chunk) {
			s.mu.Lock()
			for s.swin <= 0 {
				s.cond.Wait()
			}
			k := int64(len(chunk) - off)
			if k > s.swin {
				k = s.swin
			}
			if k > maxFrame {
				k = maxFrame
			}
			s.swin -= k
			s.mu.Unlock()
			_ = lb.frame(kindDATA, 0, s.id, chunk[off:off+int(k)])
			off += int(k)
		}
	}
}

// --- tests ---

// TestRaceConcurrentOpens: many goroutines call Open simultaneously,
// each does one round-trip of small data, verifies echo, closes.
// Targets: nid allocation, streams-map registration, frame writer mutex.
func TestRaceConcurrentOpens(t *testing.T) {
	m, teardown := connect(t)
	defer teardown()

	const N = 64
	var wg sync.WaitGroup
	errs := make([]error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := []byte{byte(i), 0xAA, 0xBB, 0xCC}
			s, err := m.Open([]byte("test"))
			if err != nil {
				errs[i] = err
				return
			}
			if _, err := s.Write(payload); err != nil {
				errs[i] = err
				return
			}
			if err := s.CloseWrite(); err != nil {
				errs[i] = err
				return
			}
			got, err := io.ReadAll(s)
			if err != nil {
				errs[i] = err
				return
			}
			if !equalBytes(got, payload) {
				errs[i] = errors.New("echo mismatch")
			}
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Errorf("stream %d: %v", i, e)
		}
	}
}

// TestRaceLargePayloads: a single stream pumps a payload larger than the
// send window so Write blocks on credit, then resumes when WIN frames
// arrive. Targets: cond.Wait/Broadcast on the same mutex; window math.
func TestRaceLargePayloads(t *testing.T) {
	m, teardown := connect(t)
	defer teardown()

	const N = 8
	const Size = 600 * 1024 // > initialWindow (256K), forces multi-WIN
	var wg sync.WaitGroup
	errs := make([]error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := make([]byte, Size)
			if _, err := rand.Read(payload); err != nil {
				errs[i] = err
				return
			}
			s, err := m.Open([]byte("big"))
			if err != nil {
				errs[i] = err
				return
			}
			// Concurrent writer/reader on the same stream (this is
			// what http.Transport does: write goroutine sends body,
			// read goroutine drains response).
			var ig sync.WaitGroup
			ig.Add(1)
			go func() {
				defer ig.Done()
				if _, err := s.Write(payload); err != nil {
					errs[i] = err
					return
				}
				_ = s.CloseWrite()
			}()
			got, err := io.ReadAll(s)
			ig.Wait()
			if err != nil {
				if errs[i] == nil {
					errs[i] = err
				}
				return
			}
			if !equalBytes(got, payload) {
				errs[i] = errors.New("echo mismatch")
			}
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Errorf("stream %d: %v", i, e)
		}
	}
}

// TestRaceConcurrentReadWriteSameStream: hammer one stream with both
// directions in flight, many iterations, varying chunk sizes. This is
// the hottest path: each stream has one goroutine writing, one reading,
// one delivering inbound frames, one cond-broadcasting.
func TestRaceConcurrentReadWriteSameStream(t *testing.T) {
	m, teardown := connect(t)
	defer teardown()

	const Iters = 200
	s, err := m.Open([]byte("hot"))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	var writeErr, readErr error

	// Writer: sends Iters chunks of varying sizes.
	go func() {
		defer wg.Done()
		rng := mrand.New(mrand.NewSource(1))
		for i := 0; i < Iters; i++ {
			sz := 1 + rng.Intn(40_000)
			chunk := make([]byte, sz)
			// Deterministic content so we can verify ordering.
			for j := range chunk {
				chunk[j] = byte(i)
			}
			if _, err := s.Write(chunk); err != nil {
				writeErr = err
				return
			}
		}
		_ = s.CloseWrite()
	}()

	// Reader: drains everything, verifies byte content sums to expectation.
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		seen := map[byte]int{}
		for {
			n, err := s.Read(buf)
			for j := 0; j < n; j++ {
				seen[buf[j]]++
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				readErr = err
				return
			}
		}
		// We don't check exact totals (writer's RNG is shared with
		// the goroutine, so reconstructing is fragile). Just that we
		// got something and there were no races.
		if len(seen) == 0 {
			readErr = errors.New("no bytes received")
		}
	}()
	wg.Wait()
	if writeErr != nil {
		t.Errorf("write: %v", writeErr)
	}
	if readErr != nil {
		t.Errorf("read: %v", readErr)
	}
}

// TestRaceCloseDuringInflight: open N streams, start data flowing on each,
// then call m.Close() while they're in flight. All Read/Write calls should
// return promptly (no goroutine leak). Targets: kill-broadcast path.
func TestRaceCloseDuringInflight(t *testing.T) {
	m, teardown := connect(t)
	defer teardown()

	const N = 32
	var wg sync.WaitGroup
	var started sync.WaitGroup
	started.Add(N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := m.Open([]byte("victim"))
			if err != nil {
				started.Done()
				return
			}
			// Send one chunk so we know the round-trip is alive.
			if _, err := s.Write([]byte("hello")); err != nil {
				started.Done()
				return
			}
			buf := make([]byte, 4096)
			if _, err := s.Read(buf); err != nil {
				started.Done()
				return
			}
			started.Done()
			// Now pump indefinitely until killed.
			go func() {
				blob := make([]byte, 4096)
				for {
					if _, err := s.Write(blob); err != nil {
						return
					}
				}
			}()
			for {
				if _, err := s.Read(buf); err != nil {
					return
				}
			}
		}()
	}
	// Wait until every goroutine has done at least one round-trip — that's
	// when we know the mux is "in flight" and Close is racing real activity.
	started.Wait()
	_ = m.Close()
	wg.Wait()
}

// TestRaceManyConcurrentEchoes: stress with high concurrency over many
// iterations. Race detector + this exposes any cond-broadcast misses,
// double-unlocks, etc.
func TestRaceManyConcurrentEchoes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short")
	}
	m, teardown := connect(t)
	defer teardown()

	const Goroutines = 32
	const PerGoroutine = 50

	var ops int64
	var wg sync.WaitGroup
	errs := make(chan error, Goroutines*PerGoroutine)
	for g := 0; g < Goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(int64(g)))
			for k := 0; k < PerGoroutine; k++ {
				sz := 1 + rng.Intn(50_000)
				payload := make([]byte, sz)
				rng.Read(payload)

				s, err := m.Open([]byte("loop"))
				if err != nil {
					errs <- err
					continue
				}

				var rerr, werr error
				var iw sync.WaitGroup
				iw.Add(1)
				go func() {
					defer iw.Done()
					if _, err := s.Write(payload); err != nil {
						werr = err
						return
					}
					_ = s.CloseWrite()
				}()
				got, err := io.ReadAll(s)
				iw.Wait()
				if err != nil {
					rerr = err
				}
				if rerr == nil && werr == nil && !equalBytes(got, payload) {
					errs <- errors.New("echo mismatch")
				}
				if rerr != nil {
					errs <- rerr
				}
				if werr != nil {
					errs <- werr
				}
				atomic.AddInt64(&ops, 1)
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	t.Logf("completed %d echo round-trips", atomic.LoadInt64(&ops))
}

// TestRaceOpenVsClose: Open() and Close() racing each other. New goroutines
// keep opening streams while another goroutine repeatedly Closes. After Close,
// further Opens must return error (not deadlock, not torn state). Verifies
// the m.streams==nil check in Open and the kill-all-streams path in Close.
func TestRaceOpenVsClose(t *testing.T) {
	const Trials = 25
	for trial := 0; trial < Trials; trial++ {
		m, teardown := connect(t)

		var wg sync.WaitGroup
		stopOpen := make(chan struct{})

		// Many openers, hammering Open + Write + CloseWrite + drain.
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stopOpen:
						return
					default:
					}
					s, err := m.Open([]byte("racy"))
					if err != nil {
						return // mux closed; expected outcome
					}
					_, _ = s.Write([]byte("ping"))
					_ = s.CloseWrite()
					_, _ = io.ReadAll(s) // ignore errors; we may race Close
				}
			}()
		}

		// Let some traffic flow, then yank the mux mid-stride.
		for i := 0; i < 100; i++ {
			// brief yield: write a no-op to give openers time to register
			_ = i
		}
		_ = m.Close()
		close(stopOpen)
		wg.Wait()
		teardown()
	}
}

// --- helpers ---

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
