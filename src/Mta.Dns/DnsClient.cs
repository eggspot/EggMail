using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using Mta.Core;

namespace Mta.Dns;

/// <summary>
/// The caching stub resolver: validates and normalizes names, builds queries, sends them through an
/// <see cref="IDnsTransport"/>, verifies and parses the answer, follows CNAMEs, and caches the result.
/// Thread-safe; share one instance per process.
/// </summary>
/// <remarks>
/// <para><b>Result semantics</b> (callers such as SPF rely on these to tell "no record" from "could not ask"):</para>
/// <list type="bullet">
/// <item><description><b>NODATA</b>: <see cref="DnsResponse.Rcode"/> is <see cref="DnsRcode.NoError"/> and <see cref="DnsResponse.Answers"/> has no record of the requested type.</description></item>
/// <item><description><b>NXDOMAIN</b>: <see cref="DnsRcode.NameError"/>; <see cref="DnsResponse.IsNxDomain"/> is true. A name that can never exist (empty label, label over 63 bytes, name over 253 characters, bytes outside printable ASCII) is answered as NXDOMAIN without any network traffic.</description></item>
/// <item><description><b>SERVFAIL, REFUSED, NOTIMP, FORMERR</b> from the resolver: returned as a normal <see cref="DnsResponse"/> with that rcode and no answers, never cached. Treat any rcode other than NoError/NameError as a temporary failure.</description></item>
/// <item><description><b>No usable answer at all</b> (every server timed out or was unreachable, the response was malformed or did not match the question, a CNAME loop or a chain deeper than <see cref="DnsResolverOptions.MaxCnameDepth"/>): a <see cref="DnsException"/> with a <see cref="DnsException.Reason"/>. This is also a temporary failure for the caller.</description></item>
/// </list>
/// <para>
/// <b>Cancellation</b>: the caller's token cancels the caller's wait only. The network query it joined keeps running to
/// completion (bounded by the transport timeouts) because other callers may share it and the answer will be cached.
/// </para>
/// <para>
/// <b>Cache clock</b>: entries expire by <see cref="IClock.UtcNow"/>; a wall clock that jumps backwards makes affected entries expire early, never live longer.
/// </para>
/// </remarks>
public sealed class DnsClient : IDnsResolver
{
    private sealed record Outcome(DnsResponse? Response, DnsException? Error);

    private readonly IDnsTransport _transport;
    private readonly DnsResolverOptions _options;
    private readonly DnsCache? _cache;
    private readonly ConcurrentDictionary<DnsCache.Key, Task<Outcome>> _inFlight = new();
    private readonly uint _minTtlSeconds;
    private readonly uint _maxTtlSeconds;
    private readonly uint _negativeCapSeconds;
    private readonly uint _defaultNegativeSeconds;

    public DnsClient(IDnsTransport transport, DnsResolverOptions? options = null, IClock? clock = null)
    {
        ArgumentNullException.ThrowIfNull(transport);
        options ??= new DnsResolverOptions();
        options.Validate();
        _transport = transport;
        _options = options;
        _minTtlSeconds = Seconds(options.MinCacheTtl);
        _maxTtlSeconds = Seconds(options.MaxCacheTtl);
        _negativeCapSeconds = Seconds(options.NegativeCacheMaxTtl);
        _defaultNegativeSeconds = Seconds(options.DefaultNegativeTtl);
        if (options.MaxCacheEntries > 0)
        {
            _cache = new DnsCache(options.MaxCacheEntries, clock ?? SystemClock.Instance);
        }
    }

    /// <summary>
    /// Creates a client with the production UDP/TCP transport. If <paramref name="options"/> names no servers they
    /// are taken from the system configuration (see <see cref="SystemDnsConfiguration"/>); with no options at all,
    /// the system's timeout and attempts are used too.
    /// </summary>
    public static DnsClient Create(DnsResolverOptions? options = null, IClock? clock = null)
    {
        options ??= DnsResolverOptions.FromSystemConfiguration();
        if (options.Servers.Count == 0)
        {
            options = options with { Servers = SystemDnsConfiguration.Discover(options.AllowPublicResolverFallback).Servers };
        }

        return new DnsClient(new UdpTcpDnsTransport(options), options, clock);
    }

    public DnsResolverOptions Options => _options;

    /// <summary>The number of answers currently cached.</summary>
    public int CachedEntryCount => _cache?.Count ?? 0;

    public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(name);
        cancellationToken.ThrowIfCancellationRequested();

        if (!DnsName.TryNormalize(name, out var normalized))
        {
            return ValueTask.FromResult(new DnsResponse { Rcode = DnsRcode.NameError });
        }

        var key = new DnsCache.Key(normalized, type);
        if (_cache is not null && _cache.TryGet(key, out var cached))
        {
            return ValueTask.FromResult(cached);
        }

        return new ValueTask<DnsResponse>(QueryNetworkAsync(key, cancellationToken));
    }

    private async Task<DnsResponse> QueryNetworkAsync(DnsCache.Key key, CancellationToken cancellationToken)
    {
        var outcome = await JoinOrStart(key).WaitAsync(cancellationToken).ConfigureAwait(false);
        if (outcome.Response is { } response)
        {
            return response;
        }

        var error = outcome.Error!;
        throw new DnsException(error.Message, error.Reason, error);
    }

    private Task<Outcome> JoinOrStart(DnsCache.Key key)
    {
        while (true)
        {
            if (_inFlight.TryGetValue(key, out var existing))
            {
                return existing;
            }

            // A query may have finished between the caller's cache miss and now.
            if (_cache is not null && _cache.TryGet(key, out var cached))
            {
                return Task.FromResult(new Outcome(cached, null));
            }

            var tcs = new TaskCompletionSource<Outcome>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (_inFlight.TryAdd(key, tcs.Task))
            {
                _ = RunQueryAsync(key, tcs);
                return tcs.Task;
            }
        }
    }

    private async Task RunQueryAsync(DnsCache.Key key, TaskCompletionSource<Outcome> completion)
    {
        Outcome outcome;
        try
        {
            var response = await ResolveAsync(key.Name, key.Type).ConfigureAwait(false);
            StoreInCache(key, response);
            outcome = new Outcome(response, null);
        }
        catch (DnsException ex)
        {
            outcome = new Outcome(null, ex);
        }
        catch (OperationCanceledException ex)
        {
            outcome = new Outcome(null, new DnsException("DNS query was cancelled by the transport.", DnsFailureReason.Timeout, ex));
        }
        catch (Exception ex)
        {
            outcome = new Outcome(null, new DnsException("DNS query failed: " + ex.Message, DnsFailureReason.Unspecified, ex));
        }

        _inFlight.TryRemove(new KeyValuePair<DnsCache.Key, Task<Outcome>>(key, completion.Task));
        completion.SetResult(outcome);
    }

    private void StoreInCache(DnsCache.Key key, DnsResponse response)
    {
        if (_cache is not null && response.Rcode is DnsRcode.NoError or DnsRcode.NameError && response.Ttl > 0)
        {
            _cache.Set(key, response, TimeSpan.FromSeconds(response.Ttl));
        }
    }

    private async Task<DnsResponse> ResolveAsync(string name, DnsRecordType type)
    {
        // CNAMEs are chased for every type except CNAME itself and ANY.
        bool chase = type is not (DnsRecordType.CNAME or DnsRecordType.ANY);
        var chain = new List<DnsRecord>();
        var visited = new HashSet<string>(StringComparer.Ordinal) { name };
        string current = name;
        bool authenticated = true;

        while (true)
        {
            var message = await ExchangeAsync(current, type).ConfigureAwait(false);
            authenticated &= message.AuthenticData;
            if (message.Rcode is not (DnsRcode.NoError or DnsRcode.NameError))
            {
                return new DnsResponse { Rcode = message.Rcode };
            }

            // Follow the CNAME chain inside this response, then keep only records that belong to the question:
            // anything else in the answer section is out of bailiwick and is dropped.
            string tail = current;
            if (chase)
            {
                while (FindCname(message.Answers, tail) is { } cname)
                {
                    if (chain.Count >= _options.MaxCnameDepth)
                    {
                        throw new DnsException($"CNAME chain for '{name}' is longer than {_options.MaxCnameDepth}.", DnsFailureReason.ResolutionLimit);
                    }

                    if (!visited.Add(cname.Target))
                    {
                        throw new DnsException($"CNAME loop while resolving '{name}'.", DnsFailureReason.ResolutionLimit);
                    }

                    chain.Add(cname);
                    tail = cname.Target;
                }
            }

            int dataStart = chain.Count;
            foreach (var record in message.Answers)
            {
                if (string.Equals(record.Name, tail, StringComparison.Ordinal) && Wanted(record, type))
                {
                    chain.Add(record);
                }
            }

            bool hasData = chain.Count > dataStart;
            bool finished = hasData
                || message.Rcode == DnsRcode.NameError
                || message.NegativeTtl is not null   // the resolver says the (final) name has no such data
                || !chase
                || string.Equals(tail, current, StringComparison.Ordinal);
            if (!finished)
            {
                // The resolver gave a CNAME without following it; ask for the target ourselves.
                current = tail;
                continue;
            }

            return BuildResponse(message, chain, hasData, authenticated);
        }
    }

    private DnsResponse BuildResponse(DnsMessage last, List<DnsRecord> answers, bool hasData, bool authenticated)
    {
        uint ttl = uint.MaxValue;
        foreach (var record in answers)
        {
            ttl = Math.Min(ttl, record.Ttl);
        }

        if (hasData)
        {
            ttl = Math.Clamp(ttl, _minTtlSeconds, _maxTtlSeconds);
        }
        else
        {
            uint negative = last.NegativeTtl ?? _defaultNegativeSeconds;
            ttl = Math.Min(Math.Min(ttl, negative), _negativeCapSeconds);
        }

        return new DnsResponse
        {
            Rcode = last.Rcode,
            AuthenticatedData = _options.TrustAuthenticatedData && authenticated,
            Answers = answers.ToArray(),
            Ttl = ttl,
        };
    }

    private static CnameRecord? FindCname(IReadOnlyList<DnsRecord> answers, string owner)
    {
        foreach (var record in answers)
        {
            if (record is CnameRecord cname && string.Equals(cname.Name, owner, StringComparison.Ordinal))
            {
                return cname;
            }
        }

        return null;
    }

    private static bool Wanted(DnsRecord record, DnsRecordType type) => type == DnsRecordType.ANY || record.Type == type;

    private async Task<DnsMessage> ExchangeAsync(string name, DnsRecordType type)
    {
        bool edns = _options.EdnsUdpPayloadSize != 0;
        while (true)
        {
            var message = await ExchangeOnceAsync(name, type, edns).ConfigureAwait(false);
            if (message.Rcode == DnsRcode.FormatError && edns)
            {
                // A server that does not understand EDNS0 answers FORMERR (RFC 6891 §7); ask again without the OPT record.
                edns = false;
                continue;
            }

            return message;
        }
    }

    private async Task<DnsMessage> ExchangeOnceAsync(string name, DnsRecordType type, bool edns)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(DnsMessageWriter.MaxQueryLength);
        try
        {
            int length = BuildQuery(buffer, name, type, edns, out ushort id);
            ReadOnlyMemory<byte> response = await _transport.ExchangeAsync(buffer.AsMemory(0, length), CancellationToken.None).ConfigureAwait(false);
            return ParseAndValidate(buffer.AsSpan(0, length), response.Span, id, name, type);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private int BuildQuery(Span<byte> destination, string name, DnsRecordType type, bool edns, out ushort id)
    {
        Span<byte> random = stackalloc byte[2 + 32];
        RandomNumberGenerator.Fill(random);
        id = BinaryPrimitives.ReadUInt16LittleEndian(random);

        Span<char> wireName = stackalloc char[DnsWire.MaxNamePresentationLength + 1];
        name.CopyTo(wireName);
        wireName = wireName[..name.Length];
        if (_options.Use0x20)
        {
            for (int i = 0; i < wireName.Length; i++)
            {
                char c = wireName[i];
                if (c is >= 'a' and <= 'z' && (random[2 + (i >> 3)] >> (i & 7) & 1) != 0)
                {
                    wireName[i] = (char)(c & ~0x20);
                }
            }
        }

        var query = new DnsQueryOptions(
            RecursionDesired: true,
            EdnsUdpPayloadSize: edns ? _options.EdnsUdpPayloadSize : (ushort)0,
            DnssecOk: edns && _options.RequestDnssecOk,
            AuthenticData: _options.TrustAuthenticatedData,
            CheckingDisabled: _options.CheckingDisabled);
        return DnsMessageWriter.WriteQuery(destination, id, wireName, type, in query);
    }

    private DnsMessage ParseAndValidate(ReadOnlySpan<byte> query, ReadOnlySpan<byte> response, ushort id, string name, DnsRecordType type)
    {
        // The cheap, allocation-free identity check first, so forged packets cost almost nothing.
        if (!DnsWire.IsResponseTo(query, response, _options.Use0x20))
        {
            throw new DnsException("DNS response does not match the query (ID, question or flags).", DnsFailureReason.ResponseMismatch);
        }

        var message = DnsMessageReader.Parse(response);
        if (message.Id != id
            || !message.Header.IsResponse
            || message.QuestionType != type
            || !string.Equals(message.QuestionName, name, StringComparison.Ordinal))
        {
            throw new DnsException("DNS response does not match the query (ID or question).", DnsFailureReason.ResponseMismatch);
        }

        if (message.Truncated)
        {
            throw new DnsException("DNS response is truncated and was not retried over TCP.", DnsFailureReason.ResponseMismatch);
        }

        return message;
    }

    private static uint Seconds(TimeSpan value) => (uint)Math.Min(Math.Max(value.TotalSeconds, 0), uint.MaxValue);
}
