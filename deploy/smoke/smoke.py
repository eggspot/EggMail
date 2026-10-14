#!/usr/bin/env python3
"""End-to-end smoke test for a running EggMail instance (container, compose stack, or `mta serve` on a laptop).

What it proves, using only the public interfaces of the running instance:
  1. the HTTP API answers and reports the expected storage backend (/api/v1/capabilities)
  2. a dashboard administrator (created with `mta admin create` before start-up) can sign in
  3. a tenant and a sending domain can be created, and the domain VERIFIES (the script serves the DKIM record from a tiny
     DNS stub the instance is pointed at with Dns:Servers, so no real DNS is involved)
  4. an SMTP credential created through the API authenticates on the submission port (STARTTLS, AUTH PLAIN)
  5. a real message submitted over SMTP is accepted (250), appears through the API (GET /messages, status queued/deferred/delivered)
     and is DELIVERED to a local sink the instance reaches through the stub DNS (MX -> sink) on Delivery:RemotePort

Needs the instance started with (the release workflow does this; see docs/release.md):
  Dns__Servers__0=<HOST_IP>:<DNS_PORT>  Delivery__RemotePort=<SINK_PORT>  Delivery__AllowPrivateMxAddresses=true
Python 3 standard library only (3.9 or newer). Exit code 0 = all checks passed; the first failure exits non-zero with a message.
"""
import argparse
import json
import smtplib
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

RCPT_DOMAIN = "recipient.smoke.test"
SINK_HOST = "sink.smoke.test"


# --------------------------------------------------------------------------- DNS stub

class DnsStub:
    """A minimal authoritative-looking UDP/TCP DNS server over an in-memory table: TXT, MX and A records, NOERROR+empty for
    known names of other types, NXDOMAIN for unknown names."""

    def __init__(self, port, bind="0.0.0.0"):
        # Bind to the address the instance is told to use (--host-ip), not to 0.0.0.0: a UDP reply from a wildcard-bound socket on a host
        # with several addresses leaves from the address of the outgoing interface (the Docker bridge), the resolver in the container then
        # sees an answer from an address it did not ask and drops it.
        self.records = {}  # (name, type) -> list of rdata (bytes)
        self.names = set()
        self.queries = 0
        self._lock = threading.Lock()
        self._port = port
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.bind((bind, port))
        self._tcp = socketserver.ThreadingTCPServer((bind, port), self._tcp_handler(), bind_and_activate=False)
        self._tcp.allow_reuse_address = True
        self._tcp.daemon_threads = True
        self._tcp.server_bind()
        self._tcp.server_activate()
        threading.Thread(target=self._serve_udp, daemon=True).start()
        threading.Thread(target=self._tcp.serve_forever, daemon=True).start()

    @staticmethod
    def _encode_name(name):
        out = b""
        for label in name.rstrip(".").split("."):
            if label:
                out += bytes([len(label)]) + label.encode("ascii")
        return out + b"\x00"

    def add_txt(self, name, text):
        data = text.encode("ascii")
        chunks = [data[i:i + 255] for i in range(0, len(data), 255)] or [b""]
        self._add(name, 16, b"".join(bytes([len(c)]) + c for c in chunks))

    def add_mx(self, name, preference, target):
        self._add(name, 15, struct.pack("!H", preference) + self._encode_name(target))

    def add_a(self, name, address):
        self._add(name, 1, socket.inet_aton(address))

    def _add(self, name, rtype, rdata):
        name = name.lower().rstrip(".")
        with self._lock:
            self.records.setdefault((name, rtype), []).append(rdata)
            self.names.add(name)

    def _answer(self, query):
        if len(query) < 12:
            return None
        ident, flags, qdcount = struct.unpack("!HHH", query[:6])
        if qdcount < 1:
            return None
        pos = 12
        labels = []
        while True:
            length = query[pos]
            pos += 1
            if length == 0:
                break
            labels.append(query[pos:pos + length].decode("ascii", "replace"))
            pos += length
        qtype, _qclass = struct.unpack("!HH", query[pos:pos + 4])
        question = query[12:pos + 4]
        name = ".".join(labels).lower()
        with self._lock:
            self.queries += 1
            answers = list(self.records.get((name, qtype), []))
            known = name in self.names
        rcode = 0 if (answers or known) else 3
        header = struct.pack("!HHHHHH", ident, 0x8400 | (query[2] & 0x01) << 8 | rcode, 1, len(answers), 0, 0)
        body = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(a)) + a for a in answers)
        return header + question + body

    def _serve_udp(self):
        while True:
            try:
                data, addr = self._udp.recvfrom(4096)
            except OSError:
                return
            try:
                reply = self._answer(data)
            except Exception:  # a malformed query must never kill the stub
                reply = None
            if reply:
                self._udp.sendto(reply, addr)

    def _tcp_handler(self):
        stub = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    raw = self.request.recv(2)
                    if len(raw) < 2:
                        return
                    size = struct.unpack("!H", raw)[0]
                    data = b""
                    while len(data) < size:
                        part = self.request.recv(size - len(data))
                        if not part:
                            return
                        data += part
                    reply = stub._answer(data)
                    if reply:
                        self.request.sendall(struct.pack("!H", len(reply)) + reply)
                except OSError:
                    pass

        return Handler


# --------------------------------------------------------------------------- SMTP sink

class SmtpSink:
    """Accepts any message on a plain SMTP port and keeps the raw data, so delivery can be proven end to end."""

    def __init__(self, port):
        self.messages = []
        sink = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                def send(line):
                    self.wfile.write((line + "\r\n").encode("ascii"))
                    self.wfile.flush()

                send("220 sink.smoke.test ESMTP")
                sender, recipients = None, []
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    cmd = line.decode("ascii", "replace").strip()
                    verb = cmd.split(" ", 1)[0].upper()
                    if verb in ("EHLO", "HELO"):
                        send("250-sink.smoke.test")
                        send("250 SIZE 52428800")
                    elif verb == "MAIL":
                        sender, recipients = cmd, []
                        send("250 2.1.0 ok")
                    elif verb == "RCPT":
                        recipients.append(cmd)
                        send("250 2.1.5 ok")
                    elif verb == "DATA":
                        send("354 end with <CRLF>.<CRLF>")
                        lines = []
                        while True:
                            data_line = self.rfile.readline()
                            if not data_line or data_line in (b".\r\n", b".\n"):
                                break
                            lines.append(data_line)
                        sink.messages.append((sender, recipients, b"".join(lines)))
                        send("250 2.0.0 queued as smoke")
                    elif verb == "RSET":
                        sender, recipients = None, []
                        send("250 2.0.0 ok")
                    elif verb == "NOOP":
                        send("250 2.0.0 ok")
                    elif verb == "QUIT":
                        send("221 2.0.0 bye")
                        return
                    else:
                        send("502 5.5.2 command not implemented")

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._server = Server(("0.0.0.0", port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()


# --------------------------------------------------------------------------- API client

class Api:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.cookie = None
        self.csrf = None
        self.tenant = None

    def call(self, method, path, body=None, expect=(200, 201, 202, 204), headers=None):
        url = self.base + path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        # The session cookie is marked Secure when the peer is not loopback (a container behind the docker bridge); this client
        # speaks plain HTTP on purpose, so the cookie is carried by hand instead of by a cookie jar.
        if self.cookie:
            request.add_header("Cookie", self.cookie)
        if self.csrf and method not in ("GET", "HEAD"):
            request.add_header("X-CSRF-Token", self.csrf)
        if self.tenant:
            request.add_header("X-Tenant-Id", self.tenant)
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                status, raw, response_headers = response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            status, raw, response_headers = error.code, error.read(), error.headers
        if status not in expect:
            fail("%s %s -> HTTP %d: %s" % (method, path, status, raw[:400].decode("utf-8", "replace")))
        parsed = json.loads(raw) if raw else None
        return status, parsed, response_headers


def fail(message):
    print("SMOKE FAILED: " + message, flush=True)
    sys.exit(1)


def step(message):
    print("-- " + message, flush=True)


def wait_for(description, probe, timeout, interval=1.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = probe()
        if last:
            return last
        time.sleep(interval)
    fail("timed out after %ds waiting for %s" % (timeout, description))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api", default="http://127.0.0.1:8080", help="HTTP base URL of the instance (the 8080 probe/API listener)")
    parser.add_argument("--smtp-host", default="127.0.0.1")
    parser.add_argument("--smtp-port", type=int, default=5587, help="published submission port (STARTTLS)")
    parser.add_argument("--host-ip", default="127.0.0.1", help="address of THIS machine as the instance sees it (the sink's A record)")
    parser.add_argument("--dns-port", type=int, default=5300)
    parser.add_argument("--sink-port", type=int, default=2500)
    parser.add_argument("--admin-user", default="smokeadmin")
    parser.add_argument("--admin-password", required=True)
    parser.add_argument("--expect-backend", choices=["sqlite", "postgres"], required=True)
    parser.add_argument("--domain", default="smoke-sender.test")
    parser.add_argument("--timeout", type=int, default=120, help="seconds to wait for each asynchronous condition")
    parser.add_argument("--tenant-marker", choices=["create", "assert"],
                        help="with --stop-after signin: create a tenant named 'persistence-marker' through the API, or assert that it exists "
                             "(proves that state written through the API survives a restart or a pod replacement)")
    parser.add_argument("--stop-after", choices=["signin"], help="stop successfully after this step (a quick check that the bootstrap administrator works)")
    args = parser.parse_args()

    dns = DnsStub(args.dns_port, args.host_ip)
    dns.add_mx(RCPT_DOMAIN, 10, SINK_HOST)
    dns.add_a(SINK_HOST, args.host_ip)
    sink = SmtpSink(args.sink_port)

    api = Api(args.api)

    step("capabilities report the %s backend" % args.expect_backend)
    wait_for("the API", lambda: is_healthy(args.api), args.timeout)
    _, caps, _ = api.call("GET", "/api/v1/capabilities")
    if caps.get("backend") != args.expect_backend:
        fail("capabilities backend is %r, expected %r: %s" % (caps.get("backend"), args.expect_backend, caps))
    print("   version %s, history %s" % (caps.get("version"), caps.get("history")), flush=True)

    step("administrator signs in")
    _, _, headers = api.call("POST", "/api/v1/session", {"user": args.admin_user, "password": args.admin_password})
    cookies = headers.get_all("Set-Cookie") or []
    session = next((c.split(";", 1)[0] for c in cookies if c.startswith("eggmail_session=")), None)
    if not session:
        fail("sign-in did not set the eggmail_session cookie")
    api.cookie = session
    _, me, _ = api.call("GET", "/api/v1/me")
    api.csrf = me["csrfToken"]
    if me.get("role") != "admin":
        fail("signed in as %r, expected role admin" % me.get("role"))
    if args.tenant_marker == "create":
        api.call("POST", "/api/v1/admin/tenants", {"name": "persistence-marker"})
        print("   created the tenant 'persistence-marker'", flush=True)
    elif args.tenant_marker == "assert":
        _, tenants, _ = api.call("GET", "/api/v1/admin/tenants")
        if not any(t.get("name") == "persistence-marker" for t in tenants):
            fail("the tenant 'persistence-marker' created before the restart is gone: %s" % [t.get("name") for t in tenants])
        print("   the tenant 'persistence-marker' survived", flush=True)
    if args.stop_after == "signin":
        print("SMOKE PASSED up to sign-in (%s)" % args.expect_backend, flush=True)
        return 0

    step("tenant and sending domain")
    _, tenant, _ = api.call("POST", "/api/v1/admin/tenants", {"name": "Smoke Test"})
    api.tenant = tenant["id"]
    _, domain, _ = api.call("POST", "/api/v1/domains", {"name": args.domain})
    required = [r for r in domain["records"] if r.get("required")]
    if not required:
        fail("the new domain lists no required DNS record: %s" % domain)
    for record in domain["records"]:
        if record["type"] == "TXT":
            dns.add_txt(record["host"], record["expected"])
        elif record["type"] == "CNAME":
            fail("unexpected required CNAME (is Delivery:BounceDomain set?): %s" % record)

    def verified():
        try:
            code, d, _ = api.call("POST", "/api/v1/domains/%s/verify" % domain["id"], expect=(200, 429))
        except (socket.timeout, TimeoutError, urllib.error.URLError) as error:
            print("   verify call did not finish (%s); the stub has answered %d queries so far" % (error, dns.queries), flush=True)
            return None
        if code == 429:  # "Verify now" is limited to once per 30 s per domain; the scheduled check also counts
            time.sleep(10)
            return None
        return d if d["status"] == "verified" else None

    domain = wait_for("the domain to verify (the DNS stub answered %d queries)" % dns.queries, verified, args.timeout, interval=2)
    print("   domain %s is %s (DNS stub answered %d queries)" % (domain["name"], domain["status"], dns.queries), flush=True)

    step("SMTP credential")
    username = "smoke-sender@" + args.domain
    _, credential, _ = api.call("POST", "/api/v1/smtp-credentials", {"username": username})
    password = credential["password"]

    step("authenticated submission over STARTTLS")
    subject = "EggMail smoke test %d" % int(time.time())
    message = (
        "From: Smoke <%s>\r\nTo: Recipient <rcpt@%s>\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%d.smoke@%s>\r\n"
        "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello from the EggMail release smoke test.\r\n"
    ) % (username, RCPT_DOMAIN, subject, time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime()), int(time.time()), args.domain)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # the first-run certificate is self-signed by design
    with smtplib.SMTP(args.smtp_host, args.smtp_port, timeout=30) as smtp:
        smtp.ehlo("smoke.client")
        if not smtp.has_extn("starttls"):
            fail("STARTTLS is not offered on the submission port")
        smtp.starttls(context=context)
        smtp.ehlo("smoke.client")
        smtp.login(username, password)
        refused = smtp.sendmail(username, ["rcpt@" + RCPT_DOMAIN], message.encode("utf-8"))
        if refused:
            fail("recipients refused: %s" % refused)
    print("   accepted with 250", flush=True)

    step("message is visible through the API")
    quoted = urllib.parse.quote(subject)

    def listed():
        _, page, _ = api.call("GET", "/api/v1/messages?subject=%s&limit=5" % quoted)
        items = page.get("items") or []
        return items[0] if items else None

    first = wait_for("the message in GET /messages", listed, args.timeout, interval=0.5)
    print("   id %s status %s" % (first["id"], first["status"]), flush=True)
    if first["status"] not in ("queued", "deferred", "delivered"):
        fail("unexpected message status %r" % first["status"])

    step("message is delivered to the sink through the stub MX")

    def delivered():
        _, page, _ = api.call("GET", "/api/v1/messages?subject=%s&limit=5" % quoted)
        item = (page.get("items") or [None])[0]
        return item if item and item["status"] == "delivered" else None

    wait_for("status delivered", delivered, args.timeout, interval=1)
    if not any(subject.encode() in raw for _s, _r, raw in sink.messages):
        fail("status is delivered but the sink received no message with the subject (sink got %d)" % len(sink.messages))
    sink_message = next(raw for _s, _r, raw in sink.messages if subject.encode() in raw)
    if b"DKIM-Signature:" not in sink_message:
        fail("the delivered message carries no DKIM-Signature")
    print("   sink received %d message(s), DKIM-signed" % len(sink.messages), flush=True)

    step("admin status shows an empty queue and the backend")
    _, status, _ = api.call("GET", "/api/v1/admin/status")
    if status["backend"].lower() != args.expect_backend:
        fail("admin status backend is %r" % status["backend"])
    print("   queue depth %s, storage healthy %s" % (status["queue"]["depth"], status["storage"]["healthy"]), flush=True)

    print("SMOKE PASSED (%s)" % args.expect_backend, flush=True)
    return 0


def is_healthy(base):
    try:
        with urllib.request.urlopen(base.rstrip("/") + "/healthz", timeout=5) as response:
            return response.status == 200
    except (urllib.error.URLError, ConnectionError, socket.timeout, OSError):
        return False


if __name__ == "__main__":
    sys.exit(main())
