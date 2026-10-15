"""The soak harness's remote MX: a plain-SMTP sink that counts every message it receives by the sequence number in its Message-ID.

The load generator (`mta-tools load --id-prefix soak`) numbers its messages `<soak.000000000042@sender-domain>` and writes the numbers of the
messages the server acknowledged to an ack log. This sink counts, per sequence number, how often the message arrived. After the run:

  acknowledged but never received      -> a LOST message (the failure the whole soak exists to find)
  received more than once              -> a duplicate (allowed only when the server flagged it possible_duplicate)

Counts live in a bytearray indexed by sequence number (one byte each, saturating at 255), so a six hour run at 100 messages/s needs about 2 MB.

Two kinds of misbehaviour can be switched on, because a real remote server misbehaves and because both are exactly the situations the delivery
engine must get right:
  tempfail_rate  answer 451 after DATA without keeping the message (the server must retry it later)
  drop_ack_rate  keep the message, then close the connection without the final reply (the server cannot know whether it was accepted:
                 it retries, the sink then sees a duplicate, and the server must have flagged it possible_duplicate)

Python 3 standard library only (3.9 or newer).
"""
import random
import re
import socketserver
import threading
import time

_MESSAGE_ID = re.compile(rb"^Message-ID:\s*<([^>\r\n]+)>", re.IGNORECASE | re.MULTILINE)
_SEQUENCE = re.compile(r"\.(\d{12})@")


class SoakSink:
    def __init__(self, port, bind="127.0.0.1", tempfail_rate=0.0, drop_ack_rate=0.0, seed=1, log=None):
        self.counts = bytearray(1 << 20)
        self.total_received = 0          # every accepted DATA, duplicates included
        self.foreign = 0                 # messages whose Message-ID is not one of ours
        self.tempfails = 0
        self.dropped_acks = 0
        self.connections = 0
        self._lock = threading.Lock()
        self._random = random.Random(seed)
        self._tempfail_rate = tempfail_rate
        self._drop_ack_rate = drop_ack_rate
        self._log = log
        sink = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                sink._session(self)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
            request_queue_size = 256

        self._server = Server((bind, port), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="sink")
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()

    # -- accounting

    def count_of(self, sequence):
        return self.counts[sequence] if 0 <= sequence < len(self.counts) else 0

    def unique_received(self):
        return sum(1 for c in self.counts if c)

    def _record(self, data):
        match = _MESSAGE_ID.search(data[:8192])
        sequence = None
        if match:
            m = _SEQUENCE.search(match.group(1).decode("ascii", "replace"))
            if m:
                sequence = int(m.group(1))
        with self._lock:
            self.total_received += 1
            if sequence is None:
                self.foreign += 1
                return
            if sequence >= len(self.counts):
                self.counts.extend(bytearray(max(len(self.counts), sequence + 1 - len(self.counts))))
            if self.counts[sequence] < 255:
                self.counts[sequence] += 1

    def _roll(self, rate):
        if rate <= 0:
            return False
        with self._lock:
            return self._random.random() < rate

    # -- one SMTP session

    def _session(self, h):
        with self._lock:
            self.connections += 1

        def send(line):
            h.wfile.write((line + "\r\n").encode("ascii"))
            h.wfile.flush()

        try:
            send("220 sink.soak.test ESMTP")
            while True:
                line = h.rfile.readline(4096)
                if not line:
                    return
                verb = line.decode("ascii", "replace").strip().split(" ", 1)[0].upper()
                if verb in ("EHLO", "HELO"):
                    send("250-sink.soak.test")
                    send("250-PIPELINING")
                    send("250 SIZE 104857600")
                elif verb in ("MAIL", "RCPT", "RSET", "NOOP"):
                    send("250 2.1.0 ok")
                elif verb == "DATA":
                    send("354 end with <CRLF>.<CRLF>")
                    data = self._read_data(h.rfile)
                    if data is None:
                        return
                    if self._roll(self._tempfail_rate):
                        with self._lock:
                            self.tempfails += 1
                        send("451 4.3.0 sink says try again later")
                        continue
                    self._record(data)
                    if self._roll(self._drop_ack_rate):
                        with self._lock:
                            self.dropped_acks += 1
                        return      # the message is kept, the client never hears so
                    send("250 2.0.0 queued as soak")
                elif verb == "QUIT":
                    send("221 2.0.0 bye")
                    return
                else:
                    send("502 5.5.2 command not implemented")
        except (OSError, ValueError):
            return

    @staticmethod
    def _read_data(rfile):
        """Reads up to the terminating CRLF.CRLF. Returns the message bytes (dot-stuffing is not undone: only the headers are read)."""
        chunks = []
        tail = b""
        while True:
            chunk = rfile.read1(65536) if hasattr(rfile, "read1") else rfile.read(65536)
            if not chunk:
                return None
            chunks.append(chunk)
            window = tail + chunk
            if b"\r\n.\r\n" in window or (len(chunks) == 1 and chunk.startswith(b".\r\n")):
                return b"".join(chunks)
            tail = window[-4:]


def wait_until(predicate, timeout, interval=1.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()
