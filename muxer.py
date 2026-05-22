"""mews mux relay. Runs on the bastion inside one SSH session channel.

Reads the mews stream-mux protocol on stdin/stdout (see mux.go). Each accepted
stream's SYN payload is a "host:port" destination; the relay dials it from
the host netns, then splices bytes in both directions until close.

Wire: type:u8 flags:u8 stream:u32-BE length:u16-BE  payload
Types: 0=SYN(payload=destination) 1=DATA 2=WIN(u32 credit)
Flags: 1=FIN (DATA only)
"""

import os, socket, struct, threading, queue

HDR = "!BBIH"
SYN, DATA, WIN = 0, 1, 2
FIN = 1
MAX, INITIAL = 32_768, 256 * 1024
# Safety caps. Client misuse is the client's problem, but the server must not
# let a buggy or hostile client OOM the bastion (and thus other processes).
STREAMS_MAX = 64    # concurrent streams per tunnel; cap on threads + sockets + memory
BACKLOG_MAX = 16    # frames per stream; ~1MB worst case per stream
EOF = object()


class Mux:
    def __init__(self, rfd, wfd):
        self.rfd, self.wfd = rfd, wfd
        self.wm = threading.Lock()
        self.streams = {}
        self.accept_q = queue.Queue()
        threading.Thread(target=self._read_loop, daemon=True).start()

    def frame(self, t, fl, sid, payload=b""):
        try:
            with self.wm:
                os.write(self.wfd, struct.pack(HDR, t, fl, sid, len(payload)))
                mv = memoryview(payload)
                while mv:
                    mv = mv[os.write(self.wfd, mv) :]
        except OSError:
            pass

    def retire(self, sid):
        # serve() calls this on exit; frees a slot for STREAMS_MAX accounting.
        self.streams.pop(sid, None)

    def _readn(self, n):
        buf = bytearray()
        while len(buf) < n:
            try:
                c = os.read(self.rfd, n - len(buf))
            except OSError:
                return None
            if not c:
                return None
            buf += c
        return bytes(buf)

    def _read_loop(self):
        try:
            while True:
                h = self._readn(8)
                if h is None:
                    break
                t, fl, sid, ln = struct.unpack(HDR, h)
                p = self._readn(ln) if ln else b""
                if p is None:
                    break
                if t == SYN:
                    if len(self.streams) >= STREAMS_MAX:
                        # cap reached: refuse without registering. Client sees
                        # immediate EOF on the stream's read side.
                        self.frame(DATA, FIN, sid)
                        continue
                    try:
                        dest = p.decode("ascii")
                    except UnicodeDecodeError:
                        self.frame(DATA, FIN, sid)
                        continue
                    s = Stream(self, sid, dest)
                    self.streams[sid] = s
                    self.accept_q.put(s)
                    continue
                # Unknown sid: silently drop. Could be a late frame for a
                # retired stream, or a frame for a SYN we refused.
                s = self.streams.get(sid)
                if s is None:
                    continue
                if t == DATA:
                    if p:
                        s.push(p)
                    if fl & FIN:
                        s.push(EOF)
                elif t == WIN:
                    s.grant(struct.unpack("!I", p[:4])[0])
        finally:
            for s in list(self.streams.values()):
                s.push(EOF)
            self.accept_q.put(None)


class Stream:
    def __init__(self, mux, sid, dest):
        self.mux, self.id, self.dest = mux, sid, dest
        self.rq = queue.Queue()
        self.buf = b""
        self.swin = INITIAL
        self.cv = threading.Condition()

    def read(self, n=65_536):
        while not self.buf:
            c = self.rq.get()
            if c is EOF:
                return None
            self.buf += c
        out, self.buf = self.buf[:n], self.buf[n:]
        self.mux.frame(WIN, 0, self.id, struct.pack("!I", len(out)))
        return out

    def write(self, s):
        o = 0
        while o < len(s):
            with self.cv:
                while self.swin <= 0:
                    self.cv.wait()
                k = min(len(s) - o, self.swin, MAX)
                self.swin -= k
            self.mux.frame(DATA, 0, self.id, s[o : o + k])
            o += k

    def close_write(self):
        self.mux.frame(DATA, FIN, self.id)

    def grant(self, d):
        with self.cv:
            self.swin += d
            self.cv.notify_all()

    def push(self, c):
        if c is EOF:
            self.rq.put(c)
            return
        # Hard backlog clamp. A well-behaved client stalls naturally at
        # INITIAL_WINDOW (we stop sending WIN when c2s blocks on the upstream);
        # this catches a client ignoring flow control. Tunnel-fatal on purpose.
        if self.rq.qsize() >= BACKLOG_MAX:
            raise RuntimeError(f"stream {self.id}: backlog {self.rq.qsize()} >= {BACKLOG_MAX}")
        self.rq.put(c)


def serve(stream):
    host, _, port = stream.dest.rpartition(":")
    try:
        sock = socket.create_connection((host.strip("[]"), int(port)), timeout=10)
    except (OSError, ValueError):
        stream.close_write()
        stream.mux.retire(stream.id)
        return

    def s2c():
        try:
            while data := sock.recv(65536):
                stream.write(data)
        except OSError:
            pass
        stream.close_write()

    def c2s():
        try:
            while data := stream.read():
                sock.sendall(data)
        except OSError:
            pass
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    t1 = threading.Thread(target=s2c, daemon=True)
    t1.start()
    t2 = threading.Thread(target=c2s, daemon=True)
    t2.start()
    t1.join()
    t2.join()
    sock.close()
    stream.mux.retire(stream.id)


def main():
    mux = Mux(0, 1)
    while (s := mux.accept_q.get()) is not None:
        threading.Thread(target=serve, args=(s,), daemon=True).start()


if __name__ == "__main__":
    main()
