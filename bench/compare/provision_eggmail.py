#!/usr/bin/env python3
"""Provisioning and DNS for the EggMail profile of bench/compare/compose.yaml (runs in a container on the bench network).

  1. serves DNS on port 53: MX of dest.test -> the sink, A of the sink, and (after step 3) the DKIM record of bench.test
  2. waits for EggMail, signs in as the bootstrap administrator
  3. creates a tenant, the sender domain bench.test, publishes its DKIM record in this DNS, waits for it to verify
  4. creates an SMTP credential and writes "user:password" to /out/auth.txt for `mta-tools load --auth`
  5. keeps running, because EggMail keeps using this DNS for the MX lookups of the destination domain

It reuses the DNS stub and API client of deploy/smoke/smoke.py (mounted at /smoke/smoke.py). Not run yet, like the rest of bench/compare.
"""
import os
import sys
import time

sys.path.insert(0, "/smoke")
import smoke  # noqa: E402  (deploy/smoke/smoke.py)

API = os.environ.get("EGGMAIL_API", "http://eggmail:8080")
PASSWORD = os.environ["BENCH_ADMIN_PASSWORD"]
ADMIN_USER = os.environ.get("BENCH_ADMIN_USER", "admin")
SINK = os.environ["SINK_ADDRESS"]
DNS_PORT = int(os.environ.get("DNS_PORT", "53"))
AUTH_FILE = os.environ.get("AUTH_FILE", "/out/auth.txt")
SENDER_DOMAIN = "bench.test"          # the sender domain of `mta-tools load`
DESTINATION_DOMAIN = "dest.test"      # the recipient domain of `mta-tools load`


def main():
    dns = smoke.DnsStub(DNS_PORT)
    dns.add_mx(DESTINATION_DOMAIN, 10, "sink.bench.test")
    dns.add_a("sink.bench.test", SINK)

    api = smoke.Api(API)
    smoke.wait_for("EggMail", lambda: smoke.is_healthy(API), 180)
    _, _, headers = api.call("POST", "/api/v1/session", {"user": ADMIN_USER, "password": PASSWORD})
    api.cookie = next(c.split(";", 1)[0] for c in headers.get_all("Set-Cookie") if c.startswith("eggmail_session="))
    _, me, _ = api.call("GET", "/api/v1/me")
    api.csrf = me["csrfToken"]
    _, tenant, _ = api.call("POST", "/api/v1/admin/tenants", {"name": "Bench"})
    api.tenant = tenant["id"]
    _, domain, _ = api.call("POST", "/api/v1/domains", {"name": SENDER_DOMAIN})
    for record in domain["records"]:
        if record["type"] == "TXT":
            dns.add_txt(record["host"], record["expected"])

    def verified():
        code, d, _ = api.call("POST", "/api/v1/domains/%s/verify" % domain["id"], expect=(200, 429))
        if code == 429:
            time.sleep(10)
            return None
        return d if d["status"] == "verified" else None

    smoke.wait_for("the sender domain to verify", verified, 180, interval=2)
    _, credential, _ = api.call("POST", "/api/v1/smtp-credentials", {"username": "bench@" + SENDER_DOMAIN})
    with open(AUTH_FILE, "w", encoding="utf-8") as handle:
        handle.write("bench@%s:%s" % (SENDER_DOMAIN, credential["password"]))
    print("provisioned: sender domain %s verified, credential written to %s" % (SENDER_DOMAIN, AUTH_FILE), flush=True)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
