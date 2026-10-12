# Mta.Dns: the DNS client

`src/Mta.Dns` is the hand-written, BCL-only DNS client (decision 4: no package references; only `Mta.Core` is referenced). It is security sensitive: every byte from the network is hostile. It does no DNSSEC validation; "authenticated" means the AD bit from a trusted local validating resolver such as Unbound (decision 6).

## Layers

```
MxResolver / extensions          RFC 5321 §5.1 target selection, TXT/A/PTR/TLSA conveniences
  DnsClient : IDnsResolver       validation, cache, coalescing, CNAME chasing, AD handling
    IDnsTransport                one query in, one response out
      UdpTcpDnsTransport         UDP, TC -> TCP, failover, anti-spoofing checks
DnsMessageWriter / DnsMessageReader / DnsWire     pure packet codec (no I/O)
DnsName                          name normalization (IDNA), reverse and TLSA names
SystemDnsConfiguration           resolv.conf / network interfaces
StaticDnsResolver                in-memory resolver for tests
```

## Public API

| Type | Purpose |
|---|---|
| `IDnsResolver.QueryAsync(name, type, ct)` | Resolve one question. Unchanged contract. |
| `DnsClient` | The production resolver. `DnsClient.Create(options?)` wires the UDP/TCP transport and discovers servers if none are configured; `new DnsClient(transport, options?, clock?)` for custom transports and tests. Thread-safe, share one instance. |
| `UdpTcpDnsTransport` | The production `IDnsTransport`. |
| `DnsResolverOptions` | Settings record (below). `DnsResolverOptions.FromSystemConfiguration()` seeds servers, timeout and attempts from the OS. |
| `DnsMessageWriter.WriteQuery(span, id, name, type, options)` | Allocation-free query builder: RFC 1035, EDNS0 OPT (RFC 6891, default payload 1232), DO, AD, CD, RD bits. |
| `DnsMessageReader.Parse(span)` | Response parser returning `DnsMessage` (header, question, answers, authority, `NegativeTtl`). |
| `DnsWire` | Header reader (`DnsHeader`), constants, `IsResponseTo(query, response, caseSensitive)` (the anti-spoofing identity check). |
| `DnsName` | `TryNormalize`/`Normalize` (IDNA, lower-case, trailing dot), `IsSubdomainOf`, `GetParent`, `ReverseArpaName(ip)`, `ReverseName(ip, zone)` (DNSBL style), `TlsaName(host, port)`. |
| `MxResolver` | `ResolveAsync(domain)` returns `MxResolution(Status, Exchangers)`; `ResolveHostAsync(host)` for a single host. Options in `MxResolverOptions`. |
| `SystemDnsConfiguration` | `ParseResolvConf`, `ReadResolvConf`, `Discover`. |
| `DnsResolverExtensions` | `GetTxtAsync`, `GetTxtTextsAsync`, `GetMxAsync`, `GetAddressesAsync`, `GetPtrNamesAsync`, `GetTlsaAsync`. These swallow rcode (empty list for NXDOMAIN/NODATA/SERVFAIL); call `QueryAsync` when the difference matters (SPF). |
| `StaticDnsResolver` | Test double. Additive: `AddCname`, `AddNs`, `AddPtr`, `AddTlsa`, `QueryCount`, `GetQueryCount(name, type)`, CNAME-loop guard. |
| `DnsException` | Now carries `Reason` (`DnsFailureReason`): `Timeout`, `Network`, `MalformedResponse`, `ResponseMismatch`, `ResolutionLimit`, `InvalidRequest`. The old constructor still works. |

## Result semantics (read this if you call `QueryAsync`)

| Situation | What you get |
|---|---|
| Records found | `Rcode = NoError`, `Answers` (CNAME records on the chain included), `Ttl` = minimum TTL clamped to the cache range |
| NODATA (name exists, no such type) | `Rcode = NoError`, empty `Answers`, `Ttl` = negative TTL |
| NXDOMAIN | `Rcode = NameError` (`IsNxDomain`), `Ttl` = negative TTL. Also returned, without network traffic, for a name that cannot exist (empty label, label over 63 bytes, over 253 characters, bytes outside printable ASCII). |
| SERVFAIL / REFUSED / NOTIMP / FORMERR from the resolver | A normal `DnsResponse` with that `Rcode`, no answers, **not cached**. |
| Nothing usable (all servers timed out or were unreachable; malformed or mismatching response; CNAME loop; chain deeper than `MaxCnameDepth`) | `DnsException` with a `Reason`. |

The last two rows are both **temporary failures** for a caller such as SPF (`temperror`): treat any `Rcode` other than `NoError`/`NameError`, and any `DnsException`, as "could not find out". Only `NoError` and `NameError` are definitive. `AuthenticatedData` is `false` unless `TrustAuthenticatedData` is set and the server set AD on every response involved.

`MxResolver` never throws for DNS failures: they become `MxResolutionStatus.TempFail`. Statuses: `Ok`, `NullMx` (RFC 7505, permanent), `NoMailHost` (permanent), `TempFail`, `NonExistentDomain` (permanent).

## Options (`DnsResolverOptions`)

| Option | Default | Meaning |
|---|---|---|
| `Servers` | empty | Resolver endpoints. Empty in `DnsClient.Create` means discover from the system. |
| `AttemptTimeout` | 2 s | First-round wait; grows by `BackoffMultiplier` (2) per round, up to `MaxAttemptTimeout` (8 s). |
| `Attempts` | 3 | Rounds over the server list. |
| `QueryTimeout` | 30 s | Upper bound for one exchange including retries and failover. |
| `EnableTcpFallback` | true | Retry over TCP (2-byte length prefix) when a UDP answer has TC. |
| `EdnsUdpPayloadSize` | 1232 | Advertised EDNS0 size; 0 disables EDNS (and DO). Otherwise at least 512. |
| `RequestDnssecOk` | false | Set DO. |
| `TrustAuthenticatedData` | false | Report AD. Only for a trusted local validating resolver (loopback). Also sets the AD query bit (RFC 6840 §5.7). |
| `CheckingDisabled` | false | Set CD. |
| `Use0x20` | false | Randomize the case of the question and require the exact echo. Off by default because resolvers that normalize case would make every query time out. |
| `MaxCacheEntries` | 10 000 | Bound on cached answers; 0 disables the cache. |
| `MinCacheTtl` / `MaxCacheTtl` | 5 s / 1 day | TTL clamp for positive answers. |
| `NegativeCacheMaxTtl` | 5 min | Cap for NXDOMAIN/NODATA (RFC 2308: SOA TTL and MINIMUM, smaller wins). |
| `DefaultNegativeTtl` | 30 s | Used when a negative answer has no SOA. |
| `MaxCnameDepth` | 8 | CNAMEs followed per question. |
| `AllowPublicResolverFallback` | false | With nothing configured, use 127.0.0.1 only; true adds 1.1.1.1 and 8.8.8.8. |

`MxResolverOptions`: `MaxMxHosts` 10, `MaxAddressesPerHost` 8, `AddressPreference` (`Ipv4First` default, `Ipv6First`, `Ipv4Only`, `Ipv6Only`), `AllowCnameExchanger` true (flagged via `MailExchanger.ResolvedViaCname`), `ExcludeSpecialAddresses` true (drops unspecified, loopback, multicast/reserved 224.0.0.0+ and broadcast; private ranges are kept for the delivery policy to decide).

## Security properties

- **Spoofing resistance.** Random 16-bit ID from `RandomNumberGenerator`; a new UDP socket per query, connected to the server, so the OS picks a fresh ephemeral source port and the kernel drops datagrams from any other address or port; every datagram must match ID, QR, opcode and the whole question section (`DnsWire.IsResponseTo`); non-matching datagrams are ignored rather than failing the query; optional 0x20. `DnsClient` repeats the check after parsing.
- **Hostile packets.** All reads are bounds-checked. Compression pointers must point strictly backwards (loops are impossible) and a name may follow at most 127 pointers (bounded CPU). Names are limited to 255 wire bytes and 63-byte labels, record data must have exactly the length its type needs, reserved label types are rejected, and a lying header cannot cause a large allocation. Unparsable input always surfaces as `DnsException(MalformedResponse)`; fuzz tests assert nothing else is thrown.
- **Bailiwick filtering.** Only records that answer the question (or sit on its CNAME chain) are kept; everything else in the answer section is dropped before caching. The additional section is never parsed or cached.
- **Names from the network** are decoded in presentation form with `\.`, `\\` and `\DDD` escapes; `DnsClient` refuses to query a name containing a backslash, so an MX or CNAME target with odd bytes cannot be followed.
- **TTLs** with the high bit set count as zero (RFC 2181 §8). The cache is bounded (16 LRU shards) and uses the injected `IClock`'s `UtcNow`; a clock that jumps backwards makes entries expire early.

## Behaviors worth knowing

- **Coalescing.** Concurrent identical questions share one network query. A caller's cancellation token cancels only that caller's wait; the shared query runs to completion (bounded by `QueryTimeout`) and its answer is cached.
- **Failover.** A server that answers SERVFAIL/REFUSED/NOTIMP/FORMERR, or whose socket fails (for example ICMP port unreachable), is skipped for the rest of that query; one that merely times out is retried in later rounds. The last server that gave a usable answer is asked first next time. If every server gave a definitive failure the last such response is returned (so the caller sees the rcode).
- **EDNS fallback.** A FORMERR to an EDNS query is retried once without the OPT record.
- **TXT** character-strings are concatenated; bytes map 1:1 to chars (Latin-1).
- **resolv.conf**: `nameserver`, `options timeout:N attempts:N` (clamped to 1..30 s and 1..5). `search`, `domain`, `ndots` are ignored. If the file names no server (or is absent, as on Windows) the DNS addresses of the operational network interfaces are used, then 127.0.0.1.

## Known gaps

- No DNSSEC validation (by design; use a local validating resolver and `TrustAuthenticatedData`).
- No serve-stale, no prefetch, no DoT/DoH, no cookies (RFC 7873), no search-list handling.
- Servers are used as given: no per-server latency tracking, only "last good server first".
- The record set is the one in `DnsTypes.cs`; other types come back as `UnknownRecord`.
- Cache expiry uses wall-clock time (`IClock.UtcNow`).

## Tests and benchmarks

`tests/Mta.Dns.Tests`: codec fixtures and round trips, truncation of every prefix, mutation and random-byte fuzz with a fixed seed, compression-loop cases, allocation tests, a hand-written loopback UDP/TCP server for transport tests (TC fallback, retry, failover, spoof rejection, 0x20, cancellation, IPv6), cache/TTL/coalescing/CNAME/AD tests with a fake clock and fake transport, MX scenarios, resolv.conf parsing. An opt-in live test runs with `EGGMAIL_TEST_LIVE_DNS=1` (`--filter Category=LiveDns`).

Benchmarks: `bench/Mta.Benchmarks/Dns/DnsCodecBenchmarks.cs` (`dotnet run -c Release --project bench/Mta.Benchmarks -- --filter "*DnsCodec*"`). A first short run on an Apple M4 (indicative only, not a published result): query build 16 ns and 0 B, identity check 10 ns and 0 B, 4-record MX response parse 254 ns and 688 B, two-string TXT parse 197 ns and 464 B.
