# Go-live checklist (owner steps)

Everything in this document is something only the owner can do: it needs a server with a public IP, a domain, accounts at real mailbox providers, a certificate authority, GitHub organization settings or money. The build and CI already prove the software against local and loopback peers ([progress.md](progress.md), "Not verified / known gaps"); this checklist closes the gap to the real internet.

Work through it in order. Each step has the same four parts:

- **Do**: the exact commands or clicks.
- **Expect**: what a correct result looks like.
- **Works if**: the single observation that tells you the step is finished.
- **If not**: what to look at first.

Examples use `example.com` for your domain, `mail.example.com` for the host that runs EggMail (its `Hostname`), `bounces.example.com` for the bounce domain and `203.0.113.10` for the server's public IPv4 address. Replace them everywhere. Commands that start with `$` run on your laptop unless the step says "on the server".

Steps 1 to 5 get one domain sending with valid SPF, DKIM and DMARC. Step 6 (security audit) and step 7 (soak) are what separates "it works" from "production-ready" in [plan.md](plan.md)'s phase 6 gate. Steps 8 to 10 are the first release and the settings around it. Do 9 early: it costs minutes and protects everything else.

| Step | What | Needs | Time |
|---|---|---|---|
| [0](#0-what-you-need-before-you-start) | Prerequisites | | 30 min |
| [1](#1-deploy-on-a-server-with-a-public-ip) | Deploy, ports, firewall, outbound port 25, PTR, HELO, volume, backup | server, hosting provider support | 1 h + provider wait |
| [2](#2-dns-records) | DNS: SPF, DKIM, DMARC, return-path, bounce MX, MTA-STS, TLS-RPT | DNS zone | 1 h + propagation |
| [3](#3-send-to-gmail-outlook-and-yahoo-and-read-the-results) | Real sending and reading `Authentication-Results` | test mailboxes | 1 h |
| [4](#4-acme-with-a-real-certificate-authority) | ACME: Cloudflare token, staging, production | Cloudflare zone | 1 h |
| [5](#5-tls-rpt-reports) | TLS-RPT reports | step 3, a day of waiting | 2 days |
| [6](#6-commission-an-independent-security-audit) | Independent security audit | budget | weeks |
| [7](#7-the-7-day-soak) | 7-day soak with PASS/FAIL criteria (`bench/soak`, [soak.md](soak.md)) | a spare server | 7 days |
| [8](#8-first-release) | Version bump, CHANGELOG, tag, verify image, flip compose defaults | | 1 h |
| [9](#9-github-settings) | Vulnerability reporting, Sponsors, tag ruleset, branch protection | org admin | 30 min |
| [10](#10-rollback-and-backup-restore-drill) | Rollback and restore drill | step 1 | 1 h |

## 0. What you need before you start

- A Linux server (a small VM is enough to start: 2 vCPU, 2 GB RAM, 20 GB disk) with a **static public IPv4 address** that is not on a public blocklist, and Docker with the compose plugin. IPv6 is optional; if the server has an IPv6 address and you do not give it the same PTR, SPF and reverse-DNS treatment, the receivers that prefer IPv6 (Gmail does) will see an unauthenticated sender. Simplest: leave IPv6 unconfigured on the host or make the records for it as well.
- A domain whose DNS you control, and a second hostname for the server. Recommended layout:

| Name | Purpose |
|---|---|
| `mail.example.com` | A record to the server. The `Hostname` of EggMail (SMTP greeting, EHLO, TLS certificate, dashboard host). Must equal the PTR of the IP |
| `bounces.example.com` | The bounce domain (`Delivery:BounceDomain`): the envelope sender of every message is `b+<signed token>@bounces.example.com`. MX to `mail.example.com` |
| `example.com` (and any other sending domain) | What your customers (or you) put in the `From:` header. Gets the DKIM record |

- Two or more test mailboxes you can read the raw headers of: a Gmail account, an Outlook.com or Microsoft 365 account, a Yahoo account. A throw-away address at [mail-tester.com](https://www.mail-tester.com) for the score check.
- A DNS provider you can edit quickly. For ACME (step 4) the zone of `mail.example.com` must be in **Cloudflare**; that is the only supported DNS provider ([operations.md](operations.md#tls-certificates-and-acme)).
- On your laptop: `dig` (package `dnsutils` or `bind-utils`; macOS has it), `openssl`, `curl`, `jq`, Python 3. Optional: `swaks`.

Set these once in your shell, they are used in every example:

```sh
export HOST=mail.example.com
export DOMAIN=example.com
export BOUNCE=bounces.example.com
export IP=203.0.113.10
```

## 1. Deploy on a server with a public IP

### 1.1 Check that outbound port 25 is open (do this before anything else)

Many cloud providers block outbound port 25 by default. EggMail delivers directly to the recipient's mail server on port 25 ([design.md §7.2](design.md#72-outbound)); without it nothing is delivered. Check **on the server**, before installing anything:

```sh
# on the server
for d in gmail.com outlook.com yahoo.com; do mx=$(dig +short MX $d | sort -n | head -1 | awk '{print $2}'); echo "== $d -> $mx"; nc -vz -w 10 $mx 25; done
# or, without nc:
timeout 10 bash -c '</dev/tcp/gmail-smtp-in.l.google.com/25' && echo open || echo blocked
# and the actual SMTP greeting:
openssl s_client -starttls smtp -connect gmail-smtp-in.l.google.com:25 -crlf -quiet </dev/null 2>&1 | head -5
```

- **Expect**: `Connection to gmail-smtp-in.l.google.com 25 port [tcp/smtp] succeeded!` (one such line per provider) and, for the `openssl` line, a `220 mx.google.com ESMTP ...` banner after the TLS handshake.
- **Works if**: all three hosts connect.
- **If not** (`timed out`, `Connection refused`, no banner): the provider blocks it. Open a support ticket asking for outbound port 25 to be unblocked for the server's IP (some providers require a short written description of the use, an account history or a payment record; say it is a transactional/outbound mail server with SPF, DKIM, DMARC and PTR in place). If the provider refuses, do not go on: either move to a provider that allows it, or use EggMail's opt-in relay fallback ([operations.md, relay routes](operations.md#relay-routes-and-per-domain-tls)), which changes the sending identity (SPF and the bounce path become the relay's business). A refused connection from your laptop at home proves nothing: run the check on the server.

Also check that the IP is not already listed (a recycled cloud IP often is):

```sh
REV=$(echo $IP | awk -F. '{print $4"."$3"."$2"."$1}')
for z in zen.spamhaus.org b.barracudacentral.org bl.spamcop.net dnsbl.sorbs.net; do printf '%-28s' $z; dig +short $REV.$z A | head -1 | grep . || echo "not listed"; done
```

- **Expect**: `not listed` on every line. A `127.0.0.x` answer means listed. Spamhaus also answers `127.255.255.x` when you query it through a public resolver (that is a refusal, not a listing: query from the server's own resolver or use their web lookup).
- **If listed**: ask the provider for a different IP, or request delisting at the list's site. Do not start sending from a listed IP.

### 1.2 DNS for the host, and the reverse DNS (PTR) request

Create the forward records first:

| Type | Name | Value |
|---|---|---|
| A | `mail.example.com` | `203.0.113.10` |
| A | (nothing else points at the sending IP) | |

Now the reverse record. **You cannot create it yourself**: it lives in the IP owner's reverse zone, so the hosting provider sets it (often a field in their control panel: "reverse DNS" or "PTR"; otherwise a ticket). Text for the ticket:

```text
Please set the reverse DNS (PTR) record of 203.0.113.10 to mail.example.com.
The forward record mail.example.com already resolves to 203.0.113.10.
This server sends transactional email and receivers require forward-confirmed reverse DNS.
```

Verify (after the provider says it is done):

```sh
$ dig -x $IP +short
mail.example.com.
$ dig +short A $HOST
203.0.113.10
```

- **Works if**: the PTR returns exactly `mail.example.com.` and the A record returns the same IP (forward-confirmed reverse DNS). Gmail, Microsoft and Yahoo all reject or junk mail from an IP without it.
- **If not**: the PTR is still the provider's default (`203-0-113-10.cust.provider.net`): ask again, or check you are asking for the right IP (an IPv6 address needs its own PTR).

### 1.3 Server preparation, firewall and ports

```sh
# on the server (Debian/Ubuntu shown)
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 ufw git
sudo systemctl enable --now docker
sudo hostnamectl set-hostname mail.example.com      # cosmetic; EggMail takes its name from the Hostname setting
```

Ports (container port to published port, from [design.md §7.1](design.md#71-listeners)):

| Public port | Direction | Why | Open to |
|---|---|---|---|
| 587 (container 5587) | in | Submission, STARTTLS, AUTH | your applications only if you can; otherwise the internet |
| 465 (container 4465) | in | Submission, implicit TLS | as above |
| 2525 | in | Alternate submission | optional; close it if unused |
| 8443 | in | Dashboard and API over HTTPS | **your own IPs only** |
| 25 (container 2526) | in | **Bounce listener** (receives bounces/DSNs/complaints for the signed bounce addresses) | the internet (it must be reachable by every mail server) |
| 8080 | loopback only | health probes | never published beyond `127.0.0.1` (the compose file already does that) |
| 25 | **out** | Delivery to recipient MX servers | the internet |
| 443 and 80 out, 53 out | out | ACME, Cloudflare API, webhooks, DNS | |

The bounce listener on 25 is what turns `550 user unknown` replies that arrive later (asynchronous bounces) into suppressions and webhooks. Open it, but see the warning in [security.md](security.md): it is the one unauthenticated surface on the internet (it accepts only signed bounce addresses plus `postmaster` and `abuse`).

Firewall with `ufw`. **Docker publishes ports by writing iptables rules that bypass `ufw`**, so a `ufw deny` does not protect a published container port. The reliable way is to publish only what you want (below) and bind sensitive ports to specific addresses in the compose file:

```sh
# on the server
sudo ufw default deny incoming && sudo ufw default allow outgoing
sudo ufw allow 22/tcp                       # ssh; restrict to your address if you can: sudo ufw allow from <your.ip> to any port 22
sudo ufw allow 25/tcp && sudo ufw allow 587/tcp && sudo ufw allow 465/tcp
sudo ufw allow from <your.office.ip> to any port 8443 proto tcp
sudo ufw enable
```

In the compose file, restrict the dashboard to your address by changing `"8443:8443"` to `"<server-private-or-public-ip>:8443:8443"` only if you front it with a VPN; otherwise protect it with the provider's cloud firewall (security group), which sits in front of Docker and is not bypassed. Prefer the cloud firewall for 8443.

### 1.4 Install (Docker Compose, SQLite)

```sh
# on the server
git clone https://github.com/eggspot/EggMail.git && cd EggMail/deploy/compose
cp .env.example .env
sed -i 's/^EGGMAIL_HOSTNAME=.*/EGGMAIL_HOSTNAME=mail.example.com/' .env
# EGGMAIL_IMAGE stays on :nightly until the first release (step 8); then pin a version.
mkdir -p secrets && chmod 700 secrets
umask 077; openssl rand -base64 24 | tr -d '\n' > secrets/admin_password.txt; chmod 644 secrets/admin_password.txt
cat secrets/admin_password.txt; echo           # note it: this is the first dashboard password
```

(`644` is not a mistake: the application runs as uid 1654 and Compose does not apply owner or mode to file secrets; the `secrets/` directory itself is `700` so only you can reach the file. [release.md](release.md#docker-compose) explains why.)

Edit `compose.yaml` to publish the bounce listener and set the bounce domain (remove the leading `#` of the port line and add the environment line):

```yaml
    environment:
      Hostname: ${EGGMAIL_HOSTNAME}
      Delivery__BounceDomain: bounces.example.com
      # Sqlite__SyncMode: Normal       # see 1.7: Off survives a process kill but NOT power loss
    ports:
      - "25:2526"
```

Start it:

```sh
docker compose pull && docker compose up -d --wait
docker compose ps
curl -s http://127.0.0.1:8080/healthz ; echo
curl -s http://127.0.0.1:8080/readyz ; echo
docker compose logs eggmail | tail -20
```

- **Expect**: `docker compose ps` shows `eggmail` as `healthy`; `healthz` prints `{"status":"ok"}`; `/readyz` prints `{"status":"ready","warnings":[ ... ]}` with warnings that include `sqlite_sync_off` and `self_signed_certificate` (both are expected at this point; the first is dealt with in 1.7, the second by step 4). The log is JSON lines and contains a start-up warning about `synchronous=OFF`.
- **Works if**: from your laptop `curl -sk https://mail.example.com:8443/api/v1/capabilities | jq .` prints `"backend": "sqlite"`, and `openssl s_client -starttls smtp -connect $HOST:587 -servername $HOST -crlf -quiet </dev/null` prints a `220 mail.example.com` banner (certificate errors are fine until step 4).
- **If not**: `docker compose logs eggmail`. Exit code 2 means a configuration error and the message names the key. `permission denied` on `/data` means the volume is not owned by uid 1654 (a bind mount; use the named volume of the compose file). `Cannot read /run/secrets/...` means the password file mode. A port already in use: another MTA (`postfix`, `exim`) listens on 25 or 587; stop and disable it.

### 1.5 First sign-in and a tenant

```sh
$ export API=https://$HOST:8443/api/v1
$ PASS='<content of secrets/admin_password.txt>'
$ curl -sk -c jar -H 'content-type: application/json' -d "{\"user\":\"admin\",\"password\":\"$PASS\"}" $API/session
{"user":"admin","role":"admin","tenantId":null}
$ CSRF=$(curl -sk -b jar $API/me | jq -r .csrfToken)
$ curl -sk -b jar -H "X-CSRF-Token: $CSRF" -H 'content-type: application/json' -d '{"name":"My company"}' $API/admin/tenants
{"id":"0192...","name":"My company","slug":"my-company","status":"active", ...}
$ export TENANT=<the id from the answer>
```

- **Works if**: the three calls return the shapes shown. You can also open `https://mail.example.com:8443/` in a browser (accept the self-signed certificate warning until step 4), sign in as `admin`, and create the tenant under **Tenants**.
- **If not**: `429 rate_limited` after ten wrong passwords (wait 15 minutes); `401` is a wrong password; the password file content is exactly the password (no trailing newline: the command above wrote none).
- **Change the bootstrap password at once**: dashboard **Account**, or `curl -sk -b jar -H "X-CSRF-Token: $CSRF" -H 'content-type: application/json' -d '{"currentPassword":"...","newPassword":"..."}' $API/me/password`.

### 1.6 HELO name

The name EggMail announces in `EHLO` is `Delivery:HeloName`, which defaults to `Hostname` (`mail.example.com`). Leave the default. It must (a) resolve to the sending IP and (b) equal the PTR from 1.2. Check what the server announces to a real peer after step 3: Gmail's raw message shows `Received: from mail.example.com (mail.example.com. [203.0.113.10])`. If the part in brackets and the name differ, fix the PTR, not the HELO.

### 1.7 Volume and durability decisions

- All state is in the Docker volume `eggmail-data` mounted at `/data` (SQLite files, certificates, DKIM keys, backups). Use a **local** disk, never network storage ([operations.md](operations.md#backups-and-restore-sqlite)). `docker volume inspect eggmail_eggmail-data` shows where it lives.
- **The default `Sqlite:SyncMode=Off` survives a process kill but not power loss or an OS crash.** For a first production deployment either use `Sqlite__SyncMode: Normal` (or `Full`) in `compose.yaml` and accept lower ingest throughput, or knowingly keep `Off`. This is your decision ([open-questions.md](open-questions.md), decision 16); pick one and write it down. Mail that was acknowledged with `250` and lost in an OS crash is not recoverable.
- Backups run by default (`Backup:Enabled=true`, every 24 hours, the newest 3 kept in `/data/backups`). That is on the **same disk**: copy them off the host (step 10 shows the restore).

```sh
# on the server: nightly copy of the backup directory to another machine
sudo crontab -e
# 30 3 * * * rsync -a --delete $(docker volume inspect eggmail_eggmail-data -f '{{.Mountpoint}}')/backups/ backup@other-host:/srv/eggmail-backups/
```

- **Works if** (the image has no shell, so look from the host): `sudo ls $(docker volume inspect eggmail_eggmail-data -f '{{.Mountpoint}}')/backups` lists an `eggmail-backup-<UTC>` directory within 24 hours, and the Prometheus metric `mta_backup_last_success_timestamp_seconds` appears on `/metrics` (loopback: `curl -s http://127.0.0.1:8080/metrics | grep backup`).

### 1.8 Time

Run NTP (`timedatectl status` shows `System clock synchronized: yes`). DKIM signatures carry a timestamp and receivers reject big skew.

## 2. DNS records

EggMail prints the exact records to publish for each sending domain ([operations.md, "Adding a sending domain and its DNS records"](operations.md#adding-a-sending-domain-and-its-dns-records)). Add the domain in the dashboard (Domains, Add domain) or with the API, and take the records from the domain's page or as a zone file:

```sh
$ curl -sk -b jar -H "X-CSRF-Token: $CSRF" -H "X-Tenant-Id: $TENANT" -H 'content-type: application/json' -d "{\"name\":\"$DOMAIN\"}" $API/domains | tee domain.json | jq '{id, status, readyToSend}'
$ export DOMAIN_ID=$(jq -r .id domain.json)
$ curl -sk -b jar -H "X-Tenant-Id: $TENANT" "$API/domains/$DOMAIN_ID/records?format=zone"
; DNS records for example.com
; DKIM (required): Lets receivers verify that mail from this domain is signed by EggMail.
egg202610._domainkey.example.com. 3600 IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqh..." "...IDAQAB"
; Return-path (required): Makes bounce messages for this domain reach EggMail.
bounce.example.com. 3600 IN CNAME bounces.example.com.
; SPF (recommended): ... ; example.com. 3600 IN TXT "v=spf1 ip4:203.0.113.10 ~all"
; DMARC (recommended): ... ; _dmarc.example.com. 3600 IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```

For a fresh installation you can instead let the server register the domain at start: `Domains__Bootstrap: example.com` in `compose.yaml` creates a `Default` tenant, the domain and its DKIM key, and writes the records to the log once (`docker compose logs eggmail | grep -A30 "DNS records for"`). `mta domains records example.com` and `mta domains check example.com` do the same offline; with SQLite the server must be stopped first.

**Set these two before you copy anything**, because the records depend on them: `Hostname` must be the fully qualified name (`mail.example.com`; with a machine-name default the MTA-STS, bounce-MX and PTR advice is left out), and `Delivery__PublicSendingIp: 203.0.113.10` in `compose.yaml` (without it, and without `Api__SpfInclude`, the SPF record is derived from the A record of `Hostname` or left out).

Only the **required** records (DKIM, and the return-path CNAME when `Delivery:BounceDomain` is set) decide verification; SPF, DMARC, TLS-RPT, MTA-STS, the bounce MX and the PTR are recommended and never block sending. The selector is `egg<YYYYMM>` of the creation month, so your selector name will differ from the example. Use the values the dashboard shows, not the ones in this document.

The state machine ([api.md](api.md#domains-domains-scope)): the domain is `pending`, checked 90 s after creation, then every 90 s for 15 minutes, then every 15 minutes for 24 hours, then hourly. The **Check DNS** button, or `POST $API/domains/$DOMAIN_ID/verify`, checks immediately (once per 30 s) and the page shows for each record OK, Missing, Invalid, Mismatch or Pending with what was found next to what is expected.

### 2.1 DKIM

Add the TXT record at the host shown (`egg202610._domainkey.example.com`) with the shown value. 2048-bit keys exceed 255 characters, so the value is more than one TXT string: most DNS panels split it automatically (Cloudflare does); if yours asks, paste the whole value and let it split, or split at 255 characters yourself without adding spaces.

```sh
$ SEL=egg202610      # the selector from the dashboard
$ dig +short TXT $SEL._domainkey.$DOMAIN
"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..." "...rest of the key..."
$ dig +short TXT $SEL._domainkey.$DOMAIN @1.1.1.1 | tr -d '" \n' | sed 's/.*p=//' | wc -c      # about 392 characters for RSA-2048
```

- **Works if**: `dig` returns the TXT value from at least two different resolvers (`@1.1.1.1`, `@8.8.8.8`) and the domain's `records[]` entry for `dkim` shows `"status": "ok"`.
- **If not** (`status: invalid`, `found` differs): a character was lost in copy and paste (usually at a line break), or the panel added quotes inside the value. `missing`: not propagated yet (wait, check the authoritative server: `dig +short NS $DOMAIN` then `dig @<that ns> TXT ...`).

### 2.2 Return-path CNAME and the bounce domain

Three records. The envelope sender (the address bounces go to) is `b+<token>@bounce.example.com` once the CNAME is verified (and `@bounces.example.com` before): receivers check SPF against that name and deliver bounces to its MX, and both resolve through the CNAME to your bounce domain:

| Type | Name | Value | Why |
|---|---|---|---|
| CNAME | `bounce.example.com` (the exact host shown as `return_path`) | `bounces.example.com` | Required record; marks the domain as using your bounce path |
| MX | `bounces.example.com` | `10 mail.example.com.` | Remote servers deliver bounces here (to the listener on port 25) |
| TXT | `bounces.example.com` | `v=spf1 ip4:203.0.113.10 ~all` | **SPF for the envelope sender**: the receiver checks SPF against the domain in `MAIL FROM`; `bounce.example.com` has no TXT of its own, so the lookup follows the CNAME to this record |

```sh
$ dig +short CNAME bounce.$DOMAIN
bounces.example.com.
$ dig +short MX $BOUNCE
10 mail.example.com.
$ dig +short TXT $BOUNCE
"v=spf1 ip4:203.0.113.10 ~all"
```

The third record is not shown by the dashboard, but without it `spf=none` appears in every `Authentication-Results` header (the dashboard's SPF advice is for the `From` domain; see 2.3). Use `-all` once you have seen `spf=pass` in step 3.

Test that the bounce listener really answers on the public port 25 (from a machine that is not the server, with outbound 25 open, for example another VPS; or use an online SMTP test such as MXToolbox's):

```sh
$ openssl s_client -starttls smtp -connect $HOST:25 -crlf -quiet </dev/null 2>&1 | head -4
220 mail.example.com ESMTP
$ swaks --to postmaster@$BOUNCE --from you@gmail.com --server $HOST --port 25 -tls --quit-after RCPT 2>&1 | tail -6
 -> RCPT TO:<postmaster@bounces.example.com>
<-  250 2.1.5 Ok
```

- **Works if**: `RCPT TO:<postmaster@bounces.example.com>` is accepted and `RCPT TO:<anyone@example.org>` is refused (`550`/`554`: the listener is not an open relay). The dashboard/API `returnPathVerified` is `true` once the CNAME is found.
- **If not**: a connection that hangs or times out means port 25 inbound is blocked (provider or the `25:2526` mapping missing). A refused `postmaster@` means `Delivery:BounceDomain` is not set to the domain in the RCPT.

> **Which build.** The envelope sender is on the sending domain's own `bounce.example.com` host (so SPF aligns with the `From` domain) only in builds that contain decision 91 ([progress.md](progress.md#plan-coverage), PR 90). Older builds, including every `nightly` before it, always used the shared bounce domain (`b+token@bounces.example.com`): SPF then passes for `bounces.example.com` but does not align with the `From` domain, and `dmarc=pass` comes from DKIM alone. Check which one you run: the `Authentication-Results` of step 3 shows `smtp.mailfrom=b+...@bounce.example.com` (new) or `@bounces.example.com` (old). The records are the same for both.

### 2.3 SPF for the sending domain (advice) and the DMARC record

SPF for the `From` domain is shown as a comment in the zone file, because most domains already have an SPF record and a second one breaks SPF: merge the mechanism into the record that exists, or uncomment the line when there is none. With `Delivery__PublicSendingIp` set it reads:

```text
example.com.   TXT  "v=spf1 ip4:203.0.113.10 ~all"
```

If you send for several customer domains, publish one record at your own name and let the customers `include:` it, and set `Api:SpfInclude` to that name so the suggestion reads `include:`:

```sh
# DNS (your own domain):  spf.example.com. TXT "v=spf1 ip4:203.0.113.10 -all"
# compose.yaml:           Api__SpfInclude: spf.example.com     # then the suggestion reads  v=spf1 include:spf.example.com ~all
```

DMARC. The suggestion is `v=DMARC1; p=none; rua=mailto:dmarc@example.com` (`Domains:DmarcPolicy` and `Domains:DmarcReportAddress` change it). Two things to decide first:

1. **A mailbox must receive the reports.** `dmarc@example.com` must exist and be read, and EggMail does not receive mail for your domain. Point `rua` at a real mailbox you read, for example `rua=mailto:dmarc-reports@example.com` on your normal mail provider. If the `rua` address is on a **different domain** than the policy domain, that other domain must authorize it with a record, or large receivers will not send reports:

```text
example.com._report._dmarc.reports-domain.example.   TXT  "v=DMARC1"
```

2. **Start at `p=none`**, read the aggregate reports for two to four weeks, and only then move to `p=quarantine` and `p=reject`. A `p=none` policy never blocks.

```sh
$ dig +short TXT _dmarc.$DOMAIN
"v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com"
$ dig +short TXT $DOMAIN | grep spf1
"v=spf1 ip4:203.0.113.10 ~all"
```

- **Works if**: both return exactly one record each (two SPF records at one name make SPF `permerror`).

### 2.4 Verify the domain

```sh
$ curl -sk -b jar -H "X-CSRF-Token: $CSRF" -H "X-Tenant-Id: $TENANT" -X POST $API/domains/$DOMAIN_ID/verify | jq '{status, readyToSend, returnPathVerified, lastError, records: [.records[] | {purpose, status}]}'
{ "status": "verified", "returnPathVerified": true, "lastError": null,
  "records": [ {"purpose":"dkim","status":"ok"}, {"purpose":"return_path","status":"ok"}, {"purpose":"spf","status":"ok"}, {"purpose":"dmarc","status":"ok"} ] }
```

- **Works if**: `status` is `verified`. Until then `POST /messages` answers `403 domain_not_verified` with a `reason`.
- **If not**: `lastError` names the first required record that is missing or wrong. Use `dig` against the authoritative name server, not only your resolver, to rule out caching; a 3600-second TTL on a record you just corrected keeps the old value for up to an hour in some resolvers.

### 2.5 MTA-STS and TLS-RPT for the bounce domain (optional but recommended)

**What applies to EggMail.** MTA-STS and TLS-RPT protect mail *to* a domain, so they matter only for a domain whose MX records point at this server (inbound mail support is planned and will make that the common case). Two situations:

- **A registered sending domain that also receives its mail on EggMail** (rare today): set `Domains__MtaStsMode: Testing` (later `Enforce`). EggMail then serves `https://mta-sts.<domain>/.well-known/mta-sts.txt` itself, the domain page lists the `_mta-sts` TXT, the `mta-sts.<domain>` CNAME and the `_smtp._tls` TXT, and port 443 of that name must reach the HTTPS listener (container port 8443) with a certificate that covers `mta-sts.<domain>` (list it in `Acme:Domains`). Details and the safe way to switch it off: [operations.md, MTA-STS](operations.md#mta-sts). Everything below is the same check, done by hand.
- **The bounce domain** (`bounces.example.com`), which EggMail receives for but which is not a registered sending domain: EggMail does not serve its policy, so publish it yourself as follows. Protecting bounces and complaint reports (they contain recipient addresses) in transit, and getting TLS reports from Google, Microsoft and others about how they reach it, is worth an hour.

Your real mailbox domain (wherever `you@example.com` lives) is the business of its mail provider, who usually publishes both.

1. **The policy file.** It must be served over HTTPS at `https://mta-sts.bounces.example.com/.well-known/mta-sts.txt` with a certificate valid for `mta-sts.bounces.example.com`, status 200, no redirects. EggMail does not serve it; use any static HTTPS host (a small web server, Cloudflare Pages or Workers with a custom hostname, an S3/CDN bucket). Content, line endings CRLF preferred, LF accepted by most:

```text
version: STSv1
mode: testing
mx: mail.example.com
max_age: 86400
```

`mx` lists the host names the certificate on port 25 will be valid for: it must be the MX host (`mail.example.com`). The certificate EggMail presents on the bounce listener is the one in its certificate store, so **do ACME (step 4) before moving the policy from `testing` to `enforce`**: a self-signed certificate would make every sender that honours `enforce` refuse to deliver bounces to you.

2. **The DNS records**:

| Type | Name | Value |
|---|---|---|
| A or CNAME | `mta-sts.bounces.example.com` | the host that serves the policy file |
| TXT | `_mta-sts.bounces.example.com` | `v=STSv1; id=20261015T000000` (change `id` whenever the policy file changes; any string up to 32 letters and digits) |
| TXT | `_smtp._tls.bounces.example.com` | `v=TLSRPTv1; rua=mailto:tlsrpt@example.com` (a mailbox you read; or `rua=https://...`) |

3. **Verify**:

```sh
$ dig +short TXT _mta-sts.$BOUNCE
"v=STSv1; id=20261015T000000"
$ dig +short TXT _smtp._tls.$BOUNCE
"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
$ curl -sS -i https://mta-sts.$BOUNCE/.well-known/mta-sts.txt | head -12
HTTP/2 200
content-type: text/plain
...
version: STSv1
mode: testing
mx: mail.example.com
max_age: 86400
```

- **Works if**: the HTTP status is exactly `200` (a `301` fails the standard), the certificate is trusted by `curl` without `-k`, and the TXT records parse. For a full check use an independent validator (for example the MTA-STS and TLS-RPT lookups at `mxtoolbox.com/SuperTool.aspx`, or `checktls.com`).
- Go to `mode: enforce` only after reports from step 5 show no failures for a week, and change the TXT `id` when you do.

## 3. Send to Gmail, Outlook and Yahoo and read the results

Create an API key and an SMTP credential (the key needs the scopes it uses; the SMTP credential needs the `send` and `keys` scopes of the creator):

```sh
$ curl -sk -b jar -H "X-CSRF-Token: $CSRF" -H "X-Tenant-Id: $TENANT" -H 'content-type: application/json' -d '{"name":"golive","scopes":["send","read","domains","webhooks","suppressions","keys"]}' $API/api-keys | tee key.json | jq '{name,prefix,key}'
$ export KEY=$(jq -r .key key.json)             # shown once: egm_<8 chars>_<43 chars>
$ curl -sk -b jar -H "X-CSRF-Token: $CSRF" -H "X-Tenant-Id: $TENANT" -H 'content-type: application/json' -d '{"username":"golive-smtp"}' $API/smtp-credentials | tee smtp.json | jq '{username,password}'
$ export SMTP_USER=golive-smtp SMTP_PASS=$(jq -r .password smtp.json)
```

### 3.1 By API

```sh
$ curl -sk $API/messages -H "Authorization: Bearer $KEY" -H 'content-type: application/json' -d "{
    \"from\":\"EggMail test <hello@$DOMAIN>\", \"to\":[\"YOURNAME@gmail.com\"],
    \"subject\":\"EggMail go-live test 1 (API)\", \"text\":\"Hello from EggMail.\", \"html\":\"<p>Hello from <b>EggMail</b>.</p>\" }"
{"id":"0192a8...","status":"queued","recipients":1}
$ ID=<the id>
$ sleep 10; curl -sk $API/messages/$ID -H "Authorization: Bearer $KEY" | jq '{status,recipients}'
$ curl -sk $API/messages/$ID/events -H "Authorization: Bearer $KEY" | jq '.[] | {type,smtpCode,mxHost,tls:{used:.tls.used,version:.tls.version,verified:.tls.verified}}'
{ "type":"queued" } ... { "type":"delivered", "smtpCode":250, "mxHost":"gmail-smtp-in.l.google.com", "tls":{"used":true,"version":"Tls13","verified":true} }
```

- **Expect**: `202` with an id; within seconds `status: delivered`, an event with `smtpCode: 250`, `tls.used: true`.
- **If not** (`deferred` with a 4xx): read the `message` of the event. `421 4.7.0 ... unusual rate of unsolicited mail` or `550-5.7.1 ... IP ... not authorized / low reputation` is Gmail judging the new IP: slow down, authenticate, warm up (below). `connect_failed` / `timeout` everywhere means port 25 is blocked (1.1). `5.7.26 unauthenticated` means DKIM/SPF failed on Gmail's side (read the next section).

### 3.2 By SMTP

Submission on 587 with STARTTLS and AUTH (works with any client; this is a standard-library Python script so you need nothing installed):

```python
# send_test.py  --  python3 send_test.py
import os, smtplib, ssl
from email.message import EmailMessage
m = EmailMessage()
m["From"] = f"EggMail test <hello@{os.environ['DOMAIN']}>"
m["To"] = os.environ["TO"]
m["Subject"] = "EggMail go-live test 2 (SMTP)"
m.set_content("Hello over SMTP submission.")
ctx = ssl.create_default_context()
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE   # remove these two lines after step 4 (real certificate)
with smtplib.SMTP(os.environ["HOST"], 587) as s:
    s.starttls(context=ctx)
    s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
    print(s.send_message(m))
```

```sh
$ TO=YOURNAME@gmail.com python3 send_test.py
{}
```

`{}` means every recipient was accepted (a `250 Queued as <id>` reply). The same with `swaks`: `swaks --to $TO --from hello@$DOMAIN --server $HOST --port 587 -tls --auth PLAIN --auth-user $SMTP_USER --auth-password "$SMTP_PASS"`. AUTH is only offered after TLS; a client that tries it before gets `530 5.7.0 Must issue a STARTTLS command first`.

Send the same two messages to an Outlook.com/Microsoft 365 mailbox and a Yahoo mailbox. Send from **a verified domain**; any other `From` is refused with `550 5.7.1` (sender policy).

### 3.3 Read the authentication results

**Gmail**: open the message, the three dots, **Show original**. The top box lists `SPF`, `DKIM` and `DMARC`; below it the raw header contains the details:

```text
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=egg202610 header.b=Ab12Cd34;
       spf=pass (google.com: domain of b+AAAA...@bounce.example.com designates 203.0.113.10 as permitted sender) smtp.mailfrom="b+AAAA...@bounce.example.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=example.com
Received: from mail.example.com (mail.example.com. [203.0.113.10])
        by mx.google.com with ESMTPS id ... (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
```

**Outlook.com / Microsoft 365**: the three dots, **View**, **View message source** (or in Outlook desktop, File, Properties, "Internet headers"). Look for `Authentication-Results: spf=pass (sender IP is 203.0.113.10) smtp.mailfrom=bounce.example.com; dkim=pass (signature was verified) header.d=example.com; dmarc=pass action=none header.from=example.com; compauth=pass reason=100`.

**Yahoo**: the three dots, **View raw message**: `Authentication-Results: mta1002.mail.yahoo.com; dkim=pass header.i=@example.com header.s=egg202610; spf=pass smtp.mailfrom=bounce.example.com; dmarc=pass(p=NONE sp=NONE dis=NONE) header.from=example.com`.

**How to read the result**:

| What you see | Meaning | Fix |
|---|---|---|
| `dkim=pass header.i=@example.com` | The signature verified and its domain is yours | Good. `header.i`/`header.d` must be your sending domain, not the host name, for DMARC alignment |
| `dkim=fail (body hash did not verify)` or `(signature did not verify)` | Something changed the message after signing (a rewriting relay or a mailing list), or a wrong key | A rare path with direct delivery; if reproducible with a plain message, report a bug with the raw message |
| `dkim=neutral (no key for signature)` / `dkim=temperror` / `dkim=none` | The receiver could not find or parse the TXT record | Re-run 2.1; check the selector in `header.s` equals the one in DNS; check for a split value |
| `spf=pass ... smtp.mailfrom=b+...@bounce.example.com` | Envelope sender authorized by the SPF record of the bounce domain (reached through the CNAME) | Good. With an older build the host is `@bounces.example.com`: SPF passes but is not aligned, and DMARC passes through DKIM (see the note in 2.2) |
| `spf=none` | The bounce domain has no SPF record | Add the TXT record of 2.2 |
| `spf=softfail` / `spf=fail` | The IP is not in the SPF record | The IP in your record differs from the connecting IP (NAT, a second address, IPv6): look at `[203.0.113.10]` in `Received` |
| `spf=temperror` / `permerror` | DNS problem / two SPF records / too many lookups | Fix the record |
| `dmarc=pass` | Aligned DKIM or SPF passed | Good |
| `dmarc=fail` with `dkim=pass` | DKIM passed but for another domain than `From` | The message was sent from a domain that is not the one that signed |
| In the spam folder with all `pass` | Reputation, not authentication | New IP and no sending history: see warm-up below |
| `Received ... (version=TLS1_3 ...)` | The hop from EggMail to the receiver used TLS | Good; `version=TLS1_2` is fine, no `version=` means plaintext |

Authentication passing is necessary, not sufficient: **a brand-new IP starts with no reputation**. Send small volumes to engaged recipients first and raise slowly over weeks (EggMail has a per-domain warm-up ramp: `Sending:WarmupEnabled=true` limits each sending domain to 50, 100, 200 ... per day from the day it was added). Enable Gmail Postmaster Tools for the domain and Microsoft SNDS/JMRP for the IP to see reputation and complaints.

### 3.4 mail-tester style check

Go to <https://www.mail-tester.com>, copy the one-off address it shows (`test-xxxx@srv1.mail-tester.com`), send it a message with a realistic subject and body (not "test"; include a link and an unsubscribe line, as content filters expect), then click "Then check your score".

```sh
$ TO=test-xxxx@srv1.mail-tester.com python3 send_test.py      # or the API call of 3.1
```

- **Expect**: a score of 9 or 10 out of 10. It lists SPF, DKIM, DMARC, reverse DNS (PTR), blocklists, `List-Unsubscribe`, HTML/text balance.
- **Typical deductions**: missing `List-Unsubscribe` (add it as a custom header in the API: `"headers":{"List-Unsubscribe":"<mailto:unsubscribe@example.com>, <https://example.com/u/123>","List-Unsubscribe-Post":"List-Unsubscribe=One-Click"}`); HTML with no text part; the SPF record not matching; a blocklisted IP.
- Alternatives that report the same data: <https://dkimvalidator.com> and <https://www.appmaildev.com/en/dkim>.

**Works if** Gmail, Outlook and Yahoo each show `dkim=pass`, `spf=pass`, `dmarc=pass`, TLS on the hop, and the messages land in the inbox (or at worst Promotions) on at least two of the three.

## 4. ACME with a real certificate authority

Until now the server uses a self-signed certificate (the dashboard and `/readyz` say so). Built-in ACME orders one certificate for the names in `Acme:Domains` with the **DNS-01** challenge through Cloudflare. It is verified in CI against the Pebble test CA only ([components/acme.md](components/acme.md)); this is its first run against a real CA and the real Cloudflare API.

### 4.1 Cloudflare token

Cloudflare dashboard, My Profile, **API Tokens**, **Create Token**, "Create Custom Token":

| Permission | Level |
|---|---|
| Zone, **Zone**, **Read** | |
| Zone, **DNS**, **Edit** | |
| Zone Resources | Include, Specific zone, `example.com` (only the zone you use; never "All zones") |

No other permission. Optionally restrict the token to the server's IP (Client IP Address Filtering) and give it an expiry. Copy the token once, then test it before putting it in EggMail:

```sh
$ export CF_TOKEN=<token>
$ curl -s https://api.cloudflare.com/client/v4/user/tokens/verify -H "Authorization: Bearer $CF_TOKEN" | jq '{success, status: .result.status}'
{ "success": true, "status": "active" }
$ curl -s "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" -H "Authorization: Bearer $CF_TOKEN" | jq '.result[] | {id, name, status}'
```

- **Works if**: `status` is `active` and the second call lists your zone (that proves `Zone:Read` and the zone scope).
- **If not**: `Invalid API Token` is a typo or a wrong header; an empty `result` is a token that does not include this zone.

Store it as a file secret readable by uid 1654, next to the admin password:

```sh
# on the server, in deploy/compose
printf '%s' "$CF_TOKEN" > secrets/cloudflare_token.txt && chmod 644 secrets/cloudflare_token.txt
```

### 4.2 Staging first

Production Let's Encrypt rate-limits failed validations and new accounts; use the staging directory until the flow works. Create `deploy/compose/compose.acme.yaml`:

```yaml
services:
  eggmail:
    environment:
      Acme__Enabled: "true"
      Acme__DirectoryUrl: https://acme-staging-v02.api.letsencrypt.org/directory
      Acme__Email: you@example.com
      Acme__Domains__0: mail.example.com
      Acme__CloudflareApiTokenFile: /run/secrets/cloudflare_token
      Acme__PropagationDelay: "00:01:00"      # the default 30 s is a guess; raise it if validation fails
    secrets:
      - cloudflare_token
secrets:
  cloudflare_token:
    file: ./secrets/cloudflare_token.txt
```

```sh
docker compose -f compose.yaml -f compose.acme.yaml up -d
docker compose logs -f eggmail | grep -i acme          # Ctrl-C when it settles
curl -sk -b jar $API/admin/certificates/acme | jq .
curl -sk -b jar $API/admin/certificates | jq '.[] | {name, subject, issuer, source, active, notAfter}'
```

(Add `Acme__Domains__1: bounces.example.com`... only if you want the same certificate to cover other names; for the bounce listener the SMTP certificate selection uses the `Hostname` certificate, so `mail.example.com` is the name that matters.)

- **Expect**: within a few minutes the renewal state shows `failures: 0`, a `lastAttemptAt` and no `lastError`, and the certificate list has an entry `source: "acme"`, `active: true`, issuer starting `(STAGING)`. In the Cloudflare DNS panel a `_acme-challenge.mail.example.com` TXT record appears briefly and is removed again.
- **Works if**: `source: acme` appears and `lastError` is null.
- **If not**: `lastError` in `GET /admin/certificates/acme` names the stage. Cloudflare `403`/`9109` = the token lacks permission or the zone; `DNS problem: NXDOMAIN looking up TXT for _acme-challenge...` after "valid" published = propagation (raise `Acme__PropagationDelay` to 2 or 3 minutes); `urn:ietf:params:acme:error:rateLimited` = wait the time it names. Failed orders retry after 10 minutes, then 20, 40, up to 6 hours; the old certificate keeps being served.

### 4.3 Production

```sh
# change Acme__DirectoryUrl in compose.acme.yaml to
#   https://acme-v02.api.letsencrypt.org/directory
docker compose -f compose.yaml -f compose.acme.yaml up -d
curl -sk -b jar -H "X-CSRF-Token: $CSRF" -H 'content-type: application/json' -d "{\"domains\":[\"$HOST\"]}" $API/admin/certificates/acme
# {"status":"pending", ...}   (202)  -- a second account is created for the production directory; the staging certificate is not re-ordered by itself
sleep 120; curl -sk -b jar $API/admin/certificates | jq '.[] | {name, issuer, source, active, notAfter}'
```

- **Works if**: a certificate with an issuer such as `Let's Encrypt` (`R10`, `R11` or `E5`... whatever the CA currently uses) and `source: acme` is `active`.

### 4.4 Verify from outside

```sh
# SMTP STARTTLS on submission, and the bounce listener
$ openssl s_client -starttls smtp -connect $HOST:587 -servername $HOST -crlf </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -dates
issuer=C = US, O = Let's Encrypt, CN = E5
subject=CN = mail.example.com
notBefore=Oct 15 10:00:00 2026 GMT
notAfter=Jan 13 10:00:00 2027 GMT
$ openssl s_client -starttls smtp -connect $HOST:587 -servername $HOST -crlf -verify_return_error </dev/null 2>&1 | grep -E "Verify return code|Protocol|Cipher is|Verification"
Verify return code: 0 (ok)
# implicit TLS submission
$ openssl s_client -connect $HOST:465 -servername $HOST </dev/null 2>&1 | grep "Verify return code"
Verify return code: 0 (ok)
# the port-25 listener (from a host with outbound 25 open)
$ openssl s_client -starttls smtp -connect $HOST:25 -servername $HOST -crlf </dev/null 2>&1 | grep "Verify return code"
Verify return code: 0 (ok)
# the dashboard/API
$ openssl s_client -connect $HOST:8443 -servername $HOST -showcerts </dev/null 2>&1 | grep -E "^ [0-9] s:|Verify return code"
 0 s:CN = mail.example.com
 1 s:C = US, O = Let's Encrypt, CN = E5
Verify return code: 0 (ok)
$ curl -sS https://$HOST:8443/healthz     # no -k any more
```

- **Works if**: `Verify return code: 0 (ok)` on all four, the chain includes the intermediate (`1 s:`), and curl needs no `-k`. Remove the two verification-disabling lines from `send_test.py` and repeat step 3.
- **If not**: `Verify return code: 18` / `20` still shows the self-signed or staging certificate: check `GET /admin/certificates`. All replicas pick a new certificate up from the database within `Tls:PollInterval` (30 s) without a restart.
- Let's Encrypt no longer emails expiry notices: alert yourself on the metric `mta_tls_certificate_expiry_seconds` below 14 days ([operations.md](operations.md#monitoring)). ACME renews at about a third of the lifetime remaining; to prove renewal works on the real CA, check after about two months that the `notBefore` date has moved.

## 5. TLS-RPT reports

Two directions, with different tests:

**A. Reports EggMail sends** (about how its own TLS to recipient domains went). EggMail records outbound TLS sessions for recipient domains that publish MTA-STS or DANE, and once a day sends one RFC 8460 report per such domain to the `rua` in its `_smtp._tls` record, over HTTPS POST or as a mail (`mailto:`) through the normal queue. Gmail publishes both, so sending to Gmail in step 3 creates the data.

1. Send a few messages to `@gmail.com` before the end of a UTC day (step 3 does that).
2. Reports for a day are sent in the first hourly run after 00:10 UTC. There is no manual trigger. Check on the next day after about 00:30 UTC.
3. Verify the target the report will go to:

```sh
$ dig +short TXT _smtp._tls.gmail.com
"v=TLSRPTv1; rua=mailto:sts-reports@google.com"
```

4. Since you cannot read Google's mailbox, **test the whole path against a domain you control** that publishes MTA-STS (testing mode is enough) and `_smtp._tls` with a `mailto:` or `https:` endpoint you read. Any domain with a real mailbox works: put the records of 2.5 on a second domain whose mail is hosted elsewhere (for example your normal company mail), send to an address there from step 3, and wait for the next UTC day.
   - `mailto:` endpoint: the report arrives as an e-mail from `tls-rpt@mail.example.com` with subject `Report Domain: <domain> Submitter: mail.example.com Report-ID: <...>` and a `.json.gz` attachment. Save the attachment and decode it:

   ```sh
   $ gunzip -c 'mail.example.com!otherdomain.example!1760486400!1760572799!abc123.json.gz' | jq .
   ```

   - `https:` endpoint: use an HTTPS URL that records requests (a Cloudflare Worker that logs the body, or a request-bin service); EggMail POSTs the gzip with `Content-Type: application/tlsrpt+gzip`, treats any 2xx as success, does not follow redirects, and needs a valid certificate on the endpoint.

   What a report looks like (RFC 8460 JSON, here for a day with 12 good sessions and 1 failure):

```json
{
  "organization-name": "mail.example.com",
  "date-range": { "start-datetime": "2026-10-15T00:00:00Z", "end-datetime": "2026-10-15T23:59:59Z" },
  "contact-info": "postmaster@mail.example.com",
  "report-id": "2026-10-15T00:00:00Z_otherdomain.example",
  "policies": [ {
    "policy": { "policy-type": "sts", "policy-string": ["version: STSv1","mode: testing","mx: mx.otherdomain.example","max_age: 86400"],
                "policy-domain": "otherdomain.example", "mx-host": ["mx.otherdomain.example"] },
    "summary": { "total-successful-session-count": 12, "total-failure-session-count": 1 },
    "failure-details": [ { "result-type": "certificate-expired", "sending-mta-ip": "203.0.113.10",
                           "receiving-mx-hostname": "mx.otherdomain.example", "receiving-ip": "198.51.100.7", "failed-session-count": 1 } ]
  } ]
}
```

   - **Works if**: one report per policy domain and day arrives, `total-successful-session-count` roughly equals the number of messages you sent there that day (one session can carry several), and `sending-mta-ip` shows your public IP. If it shows nothing, set `Delivery:PublicSendingIp` (behind NAT).
   - **If nothing arrives**: the recipient domain must publish MTA-STS or DANE for EggMail to record sessions (a plain domain is not recorded); `Tls:ReportingEnabled` must be true (default); look for `report for <domain> failed` warnings in the log (the log line category is `tlsrpt`); a failed report is retried hourly up to 6 times, then dropped. The system mail comes from `tls-rpt@<Hostname>` and is not DKIM-signed unless that name is a registered sending domain, so a receiver with an enforcing DMARC policy on `example.com` may reject it: publish an SPF record for the host name (`mail.example.com. TXT "v=spf1 ip4:203.0.113.10 -all"`).

**B. Reports about you** (other providers telling you how TLS to *your* bounce domain went): these come from the `rua` of the `_smtp._tls.bounces.example.com` record you published in 2.5, to a mailbox you read. Google, Microsoft and some others send them daily when they have delivered to you. To make the first one happen, send mail to `postmaster@bounces.example.com` from a Gmail and an Outlook account; the report arrives within a day or two as a `.json.gz` (Google) or `.json` attachment. **Works if** `total-failure-session-count` is 0 and `policy-type` is `sts` (once MTA-STS is published). Failures such as `certificate-host-mismatch` or `starttls-not-supported` mean the certificate or port-25 TLS needs attention before you set the policy to `enforce`.

## 6. Commission an independent security audit

The plan's phase 6 gate is "no open critical or high findings"; no independent review has happened ([security.md](security.md#known-gaps)). The code is hand-written protocol parsing exposed to the internet, which is exactly what an independent review is for. Do this once steps 1 to 5 work (testers need a deployed instance) and before onboarding customers.

### 6.1 Who and how

Ask three security firms with mail or network-protocol experience for a quote for a **grey-box review with source access** (not a pure black-box scan): that finds more per euro. Time-box from the design's estimate: about 2 to 4 weeks with 2 to 4 testers ([design.md §9.2](design.md#92-in-house-security-review); the cost is not estimated anywhere, so budget by quotes). Agree in writing: scope, testing window, the IP addresses they test from, an NDA, a disclosure timeline (for example 90 days), and a free **retest** of the fixes.

### 6.2 Scope list (copy into the request for quote)

| # | Area | What to examine | Where it is described |
|---|---|---|---|
| 1 | Threat model | Check the STRIDE model per boundary (SMTP in, SMTP out, DNS, storage, dashboard, key store) is complete; find missing boundaries | [security.md](security.md), [design.md §9](design.md#9-security) |
| 2 | SMTP smuggling | End-of-data variants (`\n.\r\n`, `\r.\r\n`, `\n.\n`), bare CR/LF, differences between BDAT and DATA, pipelined commands after data, the SMTP smuggling research tools | `Mta.Smtp.Protocol`, `DataScanner`; [components/smtp.md](components/smtp.md) |
| 3 | STARTTLS injection and downgrade | Plaintext commands buffered before the handshake, response injection (CVE-2011-0411 class), AUTH before TLS, outbound STARTTLS stripping, `REQUIRETLS`-like behaviours | `Mta.Smtp.Server`, `Mta.Smtp.Client`, `Mta.Tls` |
| 4 | Open relay and sender spoofing | Unauthenticated path to the queue (bounce listener), sender-policy bypass (display names, `Sender`, `Resent-*`, IDN look-alikes), tenant domain ownership | `Mta.Host/Ingest`, `Mta.Policy` |
| 5 | Authentication | SMTP AUTH PLAIN/LOGIN, API keys, session cookies, CSRF, password storage (PBKDF2), user enumeration, lockout and its use as a denial of service, session fixation, role and tenant checks on every route | `Mta.Host/Security`, `Mta.Host/Api`; [api.md](api.md#authentication) |
| 6 | API and dashboard | OWASP ASVS Level 2 on the whole API surface (authorization per object, mass assignment, SSRF, injection into SQL/headers/logs, request limits, error leaks), the strict CSP and the Preact/Vite dashboard, supply chain of the nine npm dependencies | [components/dashboard.md](components/dashboard.md) |
| 7 | Secrets | Data Protection key ring, `Secrets:KeyProtection` (Certificate and `Kms` LocalKey), DKIM private keys, ACME account key, TLS keys, relay passwords, webhook secrets: storage, logging, memory exposure, backups, the backend-switch bundle (separate key ring, passphrase-protected PKCS#12), `mta secrets rewrap` | [operations.md](operations.md#protecting-the-key-ring-secretskeyprotection), [components/switch.md](components/switch.md) |
| 8 | Multi-tenant isolation | Cross-tenant reads and writes through every endpoint and through `X-Tenant-Id`, admin versus tenant roles, suppressions and webhooks shared by accident, statistics scoping, IDOR on message, domain, key and webhook ids, the VERP/bounce path across tenants | [api.md](api.md#authentication) |
| 9 | SSRF and outbound HTTP | Webhook delivery (DNS rebinding, redirects, IPv6 mapped addresses, metadata ranges, decimal/octal IPs), MTA-STS policy fetch, TLS-RPT HTTPS POST, ACME and Cloudflare calls; relay host resolution (`Delivery:AllowPrivateMxAddresses`) | `Mta.Webhooks`, `Mta.Tls` |
| 10 | Hostile message content | MIME bombs, deep nesting, header folding, encoded-word abuse, DKIM header/body canonicalization tricks, SPF macro and lookup limits, ARC, DSN/ARF parsing on the bounce listener, NUL/CRLF injection into headers via API fields | `Mta.Mime`, `Mta.Dkim`, `Mta.Auth`, `Mta.Dsn`; fuzz targets in [security.md](security.md#fuzzing) |
| 11 | Denial of service | Connection floods and slow-loris, in-flight byte budget, oversized DATA/BDAT, recipient and command limits, API request limits, queue growth, disk full (`452`), regex/CPU amplification, unauthenticated memory use, the failed-login limiter as a lockout weapon | `Smtp:*`, `Api:*` limits in [operations.md](operations.md#configuration) |
| 12 | DNS handling | Spoofed/late responses, compression-pointer loops, CNAME chains, oversized answers, cache poisoning, DNSSEC AD-bit trust (`Dns:TrustAuthenticatedData` and the Unbound sidecar) | `Mta.Dns`; [components/dns.md](components/dns.md) |
| 13 | Storage | SQL injection (raw SQL in the SQLite hot paths), file permissions and quarantine handling, `synchronous=OFF` corruption behaviour, PostgreSQL roles (owner, runtime, read-only), migrations | `Mta.Storage*` |
| 14 | Container and deployment | Image contents, non-root, read-only filesystem, capabilities, the compose and Kubernetes manifests, NetworkPolicy, secret mounting | `Dockerfile`, `deploy/` |
| 15 | Supply chain and release pipeline | GitHub Actions workflows (permissions, pinned actions, tag-driven release, the one-job trade-off in [release.md](release.md#the-release-workflow-as-built)), attestation and SBOM verification, package-free guard for the protocol assemblies, Dependabot/NuGet/npm inventory | `.github/workflows`, `Directory.Packages.props`, `dashboard/package-lock.json` |
| 16 | Backend switch | Data-moving feature: bundle tampering, rollback, quiesce/fence races, secrets re-protection | [components/switch.md](components/switch.md) |

Explicitly out of scope: deliverability and reputation, the hosting provider, third-party mail providers, social engineering.

### 6.3 What to hand the auditors

- Repository access (it is public: <https://github.com/eggspot/EggMail>), the commit hash or release tag to freeze for the test, and a read-only fork they can push findings to if they want.
- The documents: [security.md](security.md), [design.md](design.md), [decisions.md](decisions.md), [plan.md](plan.md), [api.md](api.md), [operations.md](operations.md), [components/](components/).
- A **dedicated test environment**, deployed as in step 1 on its own IP and domain (never the production one), with: two tenants with a verified domain each, an admin account, a tenant-user account per tenant, an API key per tenant, an SMTP credential per tenant, a webhook endpoint they control, and a bounce domain. Give them the logs (JSON console) and the `/metrics` endpoint.
- The test accounts in a password manager share, with the roles written down: `admin` (all tenants), `tenant-a-user`, `tenant-b-user`, `tenant-a-apikey (send, read)`, `tenant-b-apikey`.
- A way to reach you quickly during the test, and agreement that you may restart or reset the instance.

### 6.4 Deliverables to require

- A report with an executive summary, scope and method, each finding with a CVSS 4.0 score, proof of concept, affected code location and a recommended fix, and a list of what was tested and found clean.
- A retest report after your fixes ("fixed", "partially fixed", "not fixed").
- Permission to publish a summary (builds trust in an open-source project) after the fixes ship, with the disclosure schedule you agreed.

### 6.5 After the report

Every finding becomes a pull request with a regression test (the project's rule, [security.md](security.md)). Fix SLAs in the design: critical 7 days, high 30, medium 90. Record the outcome in [progress.md](progress.md) and remove the "no external audit" line in [security.md](security.md#known-gaps) only when the retest is clean. **Works if** the retest report lists no open critical or high finding.

## 7. The 7-day soak

The only soak run so far is 14 minutes on a laptop ([progress.md](progress.md#hardening-done-after-interop-and-drills-2026-10-13)). The phase 6 gate needs 7 days. A GitHub-hosted runner stops a job after 6 hours, so the 7 days run on **a machine of yours**.

The harness is `bench/soak/run-soak.sh` with the criteria in [soak.md](soak.md) (both come with PR 92; merge it first, then `git pull`). It publishes the real host, starts it as `mta serve` next to a sink, a DNS stub and a numbered-message load generator, kills it with `kill -9` on a schedule, restores backups into a second instance, samples memory, descriptors, threads, GC and queue depth every minute and writes `verdict.json` and `summary.md`. This section says how to run it for 168 hours and adds the criteria that only matter over a week; the criteria of soak.md apply unchanged.

### 7.1 Set-up

- A **dedicated machine** of the size you will run in production (not the production server): Linux, the .NET 10 SDK (`dotnet --version`), Python 3.9 or newer, 20 GB free, and, for the PostgreSQL run, PostgreSQL 17 binaries on `PATH` (`initdb`, `pg_ctl`, `psql`, `pg_dump`, `pg_restore`, `createdb`) or Docker (the script then starts a `postgres:17` container). It must not sleep, update itself or reboot for a week: disable unattended upgrades and automatic reboots, and run under `tmux`.
- The run is **loopback only** (a sink and a DNS stub on the same machine, no real recipients). Never point a soak at real mail servers.

```sh
git clone https://github.com/eggspot/EggMail.git && cd EggMail && git checkout <the commit or tag you intend to release>
ulimit -n 65536
tmux new -s soak
# SQLite as you will run it in production (decide Sqlite:SyncMode; see 1.7), history Full:
bench/soak/run-soak.sh --hours 168 --backend sqlite --sync normal --history full --out /srv/soak/sqlite-168h
# afterwards, or on a second machine, the PostgreSQL backend:
bench/soak/run-soak.sh --hours 168 --backend postgres --sync full --history full --out /srv/soak/postgres-168h
```

The defaults (30 messages a second, a size mix up to 512 KB, a `kill -9` every 20 minutes, a backup restore every 30, the last quarter of the run without drills) are the contract of soak.md; do not lower the rate or the drill frequency to make a run pass. Raise `--rate` to your real peak if it is higher.

Check after the first hour (`tail -f /srv/soak/sqlite-168h/events.jsonl`, `tail /srv/soak/sqlite-168h/samples.csv`): load is accepted, `queue_depth` is low, a crash drill has happened and the server was ready again.

- **Expect**: a final line `PASS` (or `PASS (n criteria skipped)`) and exit code 0; `summary.md` next to `verdict.json`.
- **If a criterion fails**: [soak.md, "Interpreting a failure"](soak.md#interpreting-a-failure). A lost acknowledged message or an unflagged duplicate is a bug: stop, keep the whole results directory, open an issue. Fix, then **restart from zero**: a partial run proves nothing about a leak.

### 7.2 PASS/FAIL criteria

All of soak.md's criteria must PASS, with these readings for a 168-hour run (the numbers are theirs; the table says what to check in the result):

| # | Criterion | Where | PASS | FAIL |
|---|---|---|---|---|
| 1 | Throughput | `samples.csv` (`load_accepted`), `summary.md` | The load generator ran at least 95 % of the 168 hours; accepted messages per hour stay within 10 % of the offered rate in every hour outside a drill | An hour without load accepted for a reason that is not a drill |
| 2 | No acknowledged message lost, no unflagged duplicate | `verification.json` | `lost = 0`, `unflagged = 0` | Anything else |
| 3 | Error rate | `verdict.json` | At most 0.5 % of submissions failed outside crash windows | More |
| 4 | Memory flat | `rss_mb` (and `working_set_mb`) | Median of the last quarter of the uninterrupted tail within 20 % of the first quarter; **and** the Theil-Sen slope reported in the verdict is below 1 MB per hour | A steady climb, even if under 20 % |
| 5 | Descriptors and threads flat | `fds`, `threads` | Within `max(10, 10 %)` and `max(6, 10 %)` | A climb |
| 6 | Queue drains | final drain | `queue.depth` and `deferred` 0 after the load stops, within the drain limit | Not drained |
| 7 | Crash drills (about 380 `kill -9` in 7 days) | `events.jsonl` | Every one ready within 120 s, every acknowledged message delivered after the recovery grace | One that is not |
| 8 | Backup and restore drills (about 250) | `events.jsonl` | Every restored copy passes `integrity_check`, becomes ready, signs the administrator in, lists messages | One that does not |
| 9 | Graceful shutdown and host log | `verdict.json` | `SIGTERM` exits 0; no `Critical` or `Error` line in `host.log` that is not understood | Otherwise |

Add these checks that only a week shows (soak.md does not judge them; the data is in the results directory):

| # | Check | How | PASS | FAIL |
|---|---|---|---|---|
| A | Disk growth settles | `disk_mb` in `samples.csv`; set the retention knobs to a short value for the run with `--extra-env Retention__MetadataDays=1 --extra-env Content__RetentionDays=6` (the minimum) so that retention starts within the week | After retention starts, `disk_mb` oscillates in a band; the last day's maximum is within 15 % of the third day's | Unbounded growth, or a WAL that keeps growing (`mta_storage_sqlite_wal_size_bytes`) |
| B | Throughput does not decay | compare the latency columns of day 1 and day 7 (`lat_p95_ms`) | Day 7 within 25 % of day 1 on the same load | A slowly rising latency at constant load (index or retention cost) |
| C | Memory does not creep across days | `rss_mb` per generation | The **median RSS of day 7's last generation** within 20 % of day 2's | Each generation starting higher than the one before |
| D | Disk full behaves | once, after day 3: fill the volume until about 100 MB are left (`fallocate -l <size> /srv/soak/filler`), watch the load generator get `452` replies and `host.log` say "the disk is full", then delete the filler | Intake resumes by itself, no corruption (`mta_storage_sqlite_quarantined` 0), every acknowledged message still delivered | A crash, a quarantine, an acknowledged message lost |
| E | The image, not only the published host | on day 1 and day 7, on another machine: run the compose file of step 1 for an hour under `mta-tools load` (`dotnet run --project src/Mta.Tools -c Release -- load --help`), `docker kill`, `docker compose up -d`, check `/readyz` and the queue | The container comes back healthy, the queue resumes | Otherwise |

Record the result in [progress.md](progress.md): date, commit and image digest, machine, options, the `summary.md`, and keep `samples.csv`. **Works if** the soak PASSes for each backend you ship and A to E hold.

## 8. First release

Prerequisite: `ci` is green on `main`, steps 1 to 5 are done on the nightly build, and the soak (7) has passed on the commit you are about to release. The release procedure is fixed in [release.md](release.md#cutting-a-release); this is the concrete sequence.

1. **Branch and bump.** `<Version>` is `0.1.0` in `Directory.Build.props` already; keep it for the first release (or change it to the number you want; follow semantic versioning).

```sh
git switch main && git pull
git switch -c release/0.1.0
```

2. **CHANGELOG.** Move the entries under `## [Unreleased]` into a new section with today's date, and remove the "Nothing is released yet" sentence:

```sh
.github/scripts/changelog-section.sh 0.1.0 CHANGELOG.md    # prints the section the release will publish; must not be empty after your edit
```

   Edit `CHANGELOG.md` so it contains `## [Unreleased]` (empty) above `## [0.1.0] - 2026-MM-DD`, and add the link references at the bottom if the file uses them.

3. **Open the pull request** (`gh pr create --fill`), wait for `ci` to go green, merge it (squash). Docs-only changes skip `ci`; this one changes `Directory.Build.props` or code so it runs.

4. **Tag the merge commit on `main` and push the tag.**

```sh
git switch main && git pull
git tag -a v0.1.0 -m "EggMail 0.1.0" && git push origin v0.1.0
gh run watch $(gh run list --workflow release --limit 1 --json databaseId -q '.[0].databaseId')
```

   The workflow validates the tag (equals `Directory.Build.props`, non-empty CHANGELOG section, tag commit on `main`), reuses the green `ci` for the commit, builds the multi-arch image by digest, attests it, smoke-tests the digest, gives it the tags `v0.1.0`, `0.1` and `latest`, and creates the GitHub Release.

   - **Works if**: the run is green and `gh release view v0.1.0` shows notes, `image-digests.txt`, two SBOMs and `checksums.txt`.
   - **If not**: a failed validation names the line (version mismatch, empty CHANGELOG section). Fix it with a **new patch version**, never by moving the tag: published tags and the images they point to never change ([release.md](release.md#cutting-a-release)).

5. **Verify the image, the attestation and the SBOM** from a machine that is not logged in to GHCR:

```sh
docker logout ghcr.io
docker pull ghcr.io/eggspot/eggmail:v0.1.0
docker buildx imagetools inspect ghcr.io/eggspot/eggmail:v0.1.0 | head -12      # Digest, Manifests for linux/amd64 and linux/arm64
DIGEST=$(docker buildx imagetools inspect ghcr.io/eggspot/eggmail:v0.1.0 --format '{{json .Manifest.Digest}}' | tr -d '"')
gh attestation verify oci://ghcr.io/eggspot/eggmail@$DIGEST --repo eggspot/EggMail
# the exact command, with --source-ref and --signer-workflow, is printed in the release notes: use that one
gh release download v0.1.0 -p 'checksums.txt' -p 'sbom-*.json' -p 'image-digests.txt' -D /tmp/egg-release && (cd /tmp/egg-release && sha256sum -c checksums.txt)
jq '.packages | length' /tmp/egg-release/sbom-linux-amd64.spdx.json              # more than 10
docker run --rm ghcr.io/eggspot/eggmail:v0.1.0 --version                         # 0.1.0
```

   - **Works if**: the pull works anonymously, `gh attestation verify` prints `Verification succeeded`, `sha256sum -c` says `OK` for every file, and `--version` prints `0.1.0`.
   - **If not**: `denied` on the anonymous pull means the package is not public (GitHub, Packages, `eggmail`, Package settings, Change visibility, Public; it is public today).

6. **Flip the compose defaults from nightly to the version.** The compose files intentionally have no default image (`${EGGMAIL_IMAGE:?...}`) because `latest` did not exist. Now it does; pin a version in the example and the docs:

```sh
git switch -c chore/pin-0.1.0 origin/main
sed -i 's#^EGGMAIL_IMAGE=.*#EGGMAIL_IMAGE=ghcr.io/eggspot/eggmail:0.1#' deploy/compose/.env.example     # pin the minor line, or the digest for stricter pinning
$EDITOR deploy/compose/.env.example     # also rewrite the comment that says there is no stable release yet
$EDITOR docs/release.md docs/operations.md README.md   # quick start snippets: :nightly -> :0.1
$EDITOR deploy/kubernetes/*/kustomization.yaml          # images: newTag: nightly -> 0.1.0; imagePullPolicy Always -> IfNotPresent (release.md says so)
git commit -am "Pin the deployment examples to 0.1" && git push -u origin HEAD && gh pr create --fill
```

   `docker compose config --quiet` (with the variables from the `ci` workflow's static check) and `kustomize build` must still pass; `ci` runs them. Existing deployments update by changing `EGGMAIL_IMAGE`, `docker compose pull && docker compose up -d` (take a backup first: [operations.md](operations.md#upgrades)).

## 9. GitHub settings

All under the repository `eggspot/EggMail` (Settings) unless noted. You need organization-owner or repository-admin rights.

1. **Private vulnerability reporting** (so `SECURITY.md` and `/.well-known/security.txt` point at something that works). Settings, **Code security**, "Private vulnerability reporting", **Enable**. Or:

```sh
gh api -X PUT repos/eggspot/EggMail/private-vulnerability-reporting
gh api repos/eggspot/EggMail/private-vulnerability-reporting      # {"enabled":true}
```

   - **Works if**: the **Security** tab shows "Report a vulnerability". Decide who is notified (Settings, Code security, or the people with the Security manager role).

2. **GitHub Sponsors for the organization.** Organization page, Settings, **Sponsorship**, join the waitlist or complete the application, set up payout (a bank account in a supported region or a fiscal host) and tax forms; steps and the policy draft are in [funding.md](funding.md). This cannot be done through the API. **Works if** <https://github.com/sponsors/eggspot> loads (until then the README badge and `FUNDING.yml` link to a page that does not exist).

3. **Tag protection ruleset** (release tags must not be moved, deleted or created by anyone but the owners, because the images are tagged from them). Settings, **Rules**, **Rulesets**, New ruleset, **New tag ruleset**: name `release-tags`, enforcement **Active**, target tags matching `v*`, rules: **Restrict creations**, **Restrict updates**, **Restrict deletions**, bypass list: the repository admin role (or only the owners). As API:

```sh
gh api -X POST repos/eggspot/EggMail/rulesets --input - <<'JSON'
{ "name": "release-tags", "target": "tag", "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/v*"], "exclude": [] } },
  "rules": [ { "type": "creation" }, { "type": "update" }, { "type": "deletion" } ],
  "bypass_actors": [ { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" } ] }
JSON
```

   (`actor_id` 5 is the repository Admin role.) **Works if** `git push origin v9.9.9` from a non-admin account is rejected with "Cannot create ref due to creations being restricted". Do this **after** you have decided who tags: your own `git tag` push in step 8 needs the bypass.

4. **Branch protection on `main` requiring `ci`.** Settings, Rules, Rulesets, New branch ruleset: name `main`, Active, target the default branch, rules: **Require a pull request before merging** (1 approval if you have a second reviewer, otherwise 0 and rely on the check), **Require status checks to pass** with the check named **`build-test`** (this is the job of the `ci` workflow; the status shows as `ci / build-test`), **Block force pushes**, **Restrict deletions**, optionally **Require linear history** (the project squash-merges).

```sh
gh api -X POST repos/eggspot/EggMail/rulesets --input - <<'JSON'
{ "name": "main", "target": "branch", "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [ { "type": "pull_request", "parameters": { "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": false, "require_code_owner_review": false, "require_last_push_approval": false, "required_review_thread_resolution": false } },
             { "type": "required_status_checks", "parameters": { "strict_required_status_checks_policy": false, "required_status_checks": [ { "context": "build-test" } ] } },
             { "type": "non_fast_forward" }, { "type": "deletion" } ] }
JSON
```

   - **Works if**: a test pull request cannot be merged until `build-test` is green, and a direct push to `main` is refused.
   - **Pitfall (read before enabling)**: `ci` has `paths-ignore: docs/**, **.md` on `pull_request`. A pull request that changes only documentation never starts the workflow, so the required check stays "Expected: waiting for status" forever and the pull request can never be merged. Builds of the repository that contain decision 90 (PR 89) start the workflow on every pull request and skip the work inside the job for documentation-only changes, which a required check can live with. Before that, either merge that change first or do not mark the check required: look at `.github/workflows/ci.yml` (`paths-ignore` under `pull_request` means the old behaviour).

5. Also worth a minute: Settings, **Actions**, General: "Workflow permissions: read repository contents" (the workflows declare their own), "Require approval for first-time contributors"; **Code security**: enable Dependabot alerts and secret scanning with push protection (free for public repositories).

## 10. Rollback and backup restore drill

Do this on the soak server or a throw-away copy **before** you rely on EggMail, and again after every minor release. A backup you have never restored is not a backup.

### 10.1 Backup restore (SQLite)

Backups are `VACUUM INTO` copies of each file in `/data/backups/eggmail-backup-<UTC>/` ([operations.md](operations.md#backups-and-restore-sqlite)).

```sh
# on the server, in deploy/compose
VOL=$(docker volume inspect eggmail_eggmail-data -f '{{.Mountpoint}}')
sudo ls -1 $VOL/backups                                         # eggmail-backup-20261015T033000Z ...
# 1. mark the state: create a tenant named "restore-marker" now (dashboard or API), so you can tell whether it is in the restored data
# 2. stop, replace all four files together from ONE backup directory, start
docker compose stop eggmail
B=$(sudo ls -1 $VOL/backups | tail -1)
sudo mkdir -p $VOL/replaced-$(date +%s) && sudo mv $VOL/config.db* $VOL/queue.db* $VOL/stats.db* $VOL/history.db* $VOL/replaced-*/ 2>/dev/null
sudo cp $VOL/backups/$B/*.db $VOL/
sudo chown 1654:1654 $VOL/*.db
docker compose up -d --wait
curl -sk -b jar $API/admin/status | jq '{version, backend, uptimeSeconds, queue}'
curl -sk -b jar $API/admin/tenants | jq '.[].name'
```

- **Expect**: healthy within a minute; the tenants, domains, API keys and DKIM keys of the backup are present; `restore-marker` is **absent** if it was created after the backup (this shows you restored the old state, which is the point); the queue holds the messages that were queued at backup time.
- **Works if**: you can sign in, `domains` still verify (`POST /domains/{id}/verify`), a test message sends and is delivered with a valid DKIM signature (Gmail `dkim=pass`), and `mta_storage_sqlite_quarantined` is 0.
- **If not**: a file from a different backup directory mixed in (they must come from one directory) produces a start failure or a quarantine; the previous files are in `replaced-*`: put them back and retry. The DKIM private keys are encrypted with the Data Protection key ring that lives in `config.db`; if you also use `Secrets:KeyProtection=Certificate` or `Kms`, the restored data needs **the same certificate or key file**: keep them backed up separately from the data and test that too.
- Mail accepted after the backup is lost; this is a property of backups, not a bug. Restore from a **copy off the host** at least once: the point of the copy is surviving the loss of the machine.

PostgreSQL deployments: use `pg_dump` / managed backups and test `pg_restore` into an empty database, then start EggMail against it with the same `Secrets` configuration.

### 10.2 Rollback to the previous release

```sh
# before upgrading
docker compose stop eggmail && sudo tar -C $(dirname $VOL) -czf /root/eggmail-pre-upgrade-$(date +%F).tgz $(basename $VOL) && docker compose start eggmail   # or use the newest backup
# upgrade
sed -i 's#^EGGMAIL_IMAGE=.*#EGGMAIL_IMAGE=ghcr.io/eggspot/eggmail:0.2#' .env && docker compose pull && docker compose up -d --wait
# roll back: the schema may have moved forward, so a newer database cannot be opened by the old image
docker compose stop eggmail
sudo rm -rf $VOL/*.db* && sudo tar -C $(dirname $VOL) -xzf /root/eggmail-pre-upgrade-<date>.tgz     # restore the pre-upgrade data
sed -i 's#^EGGMAIL_IMAGE=.*#EGGMAIL_IMAGE=ghcr.io/eggspot/eggmail:0.1#' .env && docker compose up -d --wait
docker compose exec eggmail /app/mta --version      # the image has no shell, but the binary can be executed directly
```

(Only the literal `*.db*` files inside the data volume are removed in this example; do not clear the whole volume directory, it holds the backups and quarantine evidence too.)

- **Expect**: an old image refuses to start on a newer schema (the message says the schema is newer than it knows): that is the signal to restore the pre-upgrade data, as above. Schema changes are additive within a roll-forward, but there is no down-migration: **rollback means restoring the pre-upgrade backup**, which loses mail accepted since ([operations.md](operations.md#upgrades)).
- **Works if**: after the rollback `--version` shows the old version, the data is the pre-upgrade data, and a test message is delivered.
- **PostgreSQL / several replicas**: roll forward only; restore the database snapshot to go back ([operations.md](operations.md#running-more-than-one-replica)).

### 10.3 Switching the backend (SQLite to PostgreSQL) has its own rollback

The guided switch in the dashboard (**Storage switch**) and `mta migrate-storage` keep the source read-only until you finalize, so rolling back before finalize is a button: [components/switch.md](components/switch.md). Rehearse it once on the soak server with realistic data before you ever need it.

## When everything above is done

Record in [progress.md](progress.md) which steps passed, with dates, the image digest and links to the soak result and the audit report, and move the matching lines out of "Not verified / known gaps". Only then is "production-ready" a claim the plan supports.
