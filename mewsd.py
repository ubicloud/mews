# mews host-namespace relay. Run by mews inside one SSH session channel on the
# bastion: listens on a pathname UNIX socket and relays each connection to a
# TCP target. Exits (and unlinks the socket) when its stdin reaches EOF -- the
# SSH channel closed -- or, as a backstop, when its parent process dies.
# argv: <socket-path> <host> <port>
import asyncio, os, sys

sock, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])


async def pump(r, w):
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except OSError:
        pass
    finally:
        w.close()


async def serve(cr, cw):
    try:
        ur, uw = await asyncio.open_connection(host, port)
    except OSError:
        cw.close()
        return
    await asyncio.gather(pump(cr, uw), pump(ur, cw))


async def main():
    if os.path.lexists(sock):
        os.unlink(sock)
    server = await asyncio.start_unix_server(serve, path=sock)
    os.chmod(sock, 0o600)
    loop, stop = asyncio.get_running_loop(), asyncio.Event()

    def on_stdin():
        if not os.read(0, 65536):          # EOF on the SSH channel
            loop.remove_reader(0)
            stop.set()
    loop.add_reader(0, on_stdin)

    try:                                   # backstop: parent process dies
        pfd = os.pidfd_open(os.getppid())

        def on_parent_death():
            loop.remove_reader(pfd)        # pidfd is level-triggered; disarm once
            stop.set()
        loop.add_reader(pfd, on_parent_death)
    except (AttributeError, OSError):
        pass

    print("READY", flush=True)             # mews waits for this before dialing
    await stop.wait()
    server.close()
    await server.wait_closed()


try:
    asyncio.run(main())
finally:
    if os.path.lexists(sock):
        os.unlink(sock)
