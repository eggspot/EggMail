using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;
using Mta.Core;
using Mta.Storage;

namespace Mta.Host.Tls;

/// <summary>Where the built-in HTTP-01 listener finds the answer for a token.</summary>
public interface IHttpChallengeResponder
{
    /// <summary>The key authorization to answer <paramref name="token"/> with, or null when no order of any replica is waiting for it.</summary>
    ValueTask<string?> FindKeyAuthorizationAsync(string token, CancellationToken cancellationToken);
}

/// <summary>
/// The HTTP-01 answers of the orders in flight (decision 87). The replica that holds the renewal lease publishes the token it got from the CA; the CA
/// then connects to whichever replica the load balancer picks, and that one has to answer. So a published token is kept twice: in this process (the
/// replica that ordered answers without touching the database) and in the config store, in the <c>challenge_state_json</c> column of the certificate's
/// renewal row (part of decision K's ACME state), from which every other replica's listener reads it.
/// <para>
/// The listener is reachable from the internet, so the database is protected from it: only a token of plausible shape gets here, and the store is read
/// as one snapshot of all published tokens, by one request at a time and not more often than <see cref="RefreshInterval"/>.
/// </para>
/// </summary>
public sealed class Http01Challenges : IHttpChallengePublisher, IHttpChallengeResponder
{
    /// <summary>A published token that its owner never removed (crashed replica) stops being answered after this long; an order takes minutes at most.</summary>
    public static readonly TimeSpan TokenLifetime = TimeSpan.FromHours(2);

    /// <summary>The store is read at most this often (a CA asks within a fraction of a second of publishing; an attacker's guesses are bounded).</summary>
    public static readonly TimeSpan DefaultRefreshInterval = TimeSpan.FromMilliseconds(50);

    private readonly IConfigStore _config;
    private readonly IClock _clock;
    private readonly IMtaLog _log;
    private readonly ConcurrentDictionary<string, (string KeyAuthorization, DateTimeOffset Until)> _local = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly SemaphoreSlim _readGate = new(1, 1);
    private readonly long _refreshTicks;
    private volatile Dictionary<string, (string KeyAuthorization, DateTimeOffset Until)> _snapshot = [];
    private long _snapshotAt;   // Stopwatch timestamp of the last read of the store; 0: never
    private volatile string? _unavailable;
    private volatile bool _starting;
    private readonly TaskCompletionSource _decided = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Http01Challenges(IConfigStore config, IClock? clock = null, IMtaLog? log = null, TimeSpan? refreshInterval = null)
    {
        _config = config;
        _clock = clock ?? SystemClock.Instance;
        _log = log ?? NullMtaLog.Instance;
        RefreshInterval = refreshInterval ?? DefaultRefreshInterval;
        _refreshTicks = (long)(RefreshInterval.TotalSeconds * Stopwatch.Frequency);
    }

    public TimeSpan RefreshInterval { get; }

    /// <summary>The runtime starts a built-in listener: orders wait for its first attempt to bind before they ask the CA to validate.</summary>
    public void ExpectListener() => _starting = true;

    /// <summary>The listener has bound its port.</summary>
    internal void ListenerBound()
    {
        _unavailable = null;
        _decided.TrySetResult();
    }

    /// <summary>The listener cannot bind its port, for <paramref name="reason"/>; <see cref="AcmeRenewalService"/> then does not ask the CA to validate.</summary>
    internal void ListenerFailed(string reason)
    {
        _unavailable = reason;
        _decided.TrySetResult();
    }

    /// <summary>Why tokens cannot be answered right now, or null (also null while a listener has not tried yet).</summary>
    public string? UnavailableReason => _unavailable;

    public async ValueTask<string?> WaitUntilReadyAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (_starting && !_decided.Task.IsCompleted)
        {
            try
            {
                await _decided.Task.WaitAsync(timeout, cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                return "The HTTP-01 listener has not started.";
            }
        }

        return _unavailable;
    }

    /// <summary>The shape of an ACME token (RFC 8555 section 8.1: base64url, at least 128 bits of entropy). Anything else is not looked up.</summary>
    public static bool IsPlausibleToken(ReadOnlySpan<char> token)
    {
        if (token.Length is < 16 or > 256)
        {
            return false;
        }

        foreach (char c in token)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            {
                return false;
            }
        }

        return true;
    }

    public async ValueTask PublishAsync(string certificateName, string token, string keyAuthorization, CancellationToken cancellationToken)
    {
        if (!IsPlausibleToken(token))
        {
            throw new AcmeException("The CA sent an HTTP-01 token that is not valid base64url text.");
        }

        var until = _clock.UtcNow + TokenLifetime;
        _local[token] = (keyAuthorization, until);
        await UpdateSharedAsync(certificateName, tokens => tokens[token] = (keyAuthorization, until), cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask RemoveAsync(string certificateName, string token, CancellationToken cancellationToken)
    {
        _local.TryRemove(token, out _);
        await UpdateSharedAsync(certificateName, tokens => tokens.Remove(token), cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask UpdateSharedAsync(string certificateName, Action<Dictionary<string, (string KeyAuthorization, DateTimeOffset Until)>> change, CancellationToken ct)
    {
        await _writeGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var row = (await _config.GetAcmeRenewalsAsync(ct).ConfigureAwait(false)).FirstOrDefault(r => r.CertificateName == certificateName);
            var tokens = Parse(row?.ChallengeStateJson, _clock.UtcNow);
            change(tokens);
            await _config.SetAcmeRenewalChallengeStateAsync(certificateName, tokens.Count == 0 ? null : Serialize(tokens), ct).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    public async ValueTask<string?> FindKeyAuthorizationAsync(string token, CancellationToken cancellationToken)
    {
        if (!IsPlausibleToken(token))
        {
            return null;
        }

        var now = _clock.UtcNow;
        if (_local.TryGetValue(token, out var own) && own.Until > now)
        {
            return own.KeyAuthorization;
        }

        // The snapshot of the store answers while it is fresh (a token another replica has since removed is not answered for longer than
        // the refresh interval), and a token it does not hold is not looked up again before it is stale: the store is not asked for every guess.
        if (!RefreshDue())
        {
            return _snapshot.TryGetValue(token, out var known) && known.Until > now ? known.KeyAuthorization : null;
        }

        await _readGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (RefreshDue())
            {
                await RefreshAsync(now, cancellationToken).ConfigureAwait(false);
            }

            return _snapshot.TryGetValue(token, out var found) && found.Until > now ? found.KeyAuthorization : null;
        }
        finally
        {
            _readGate.Release();
        }
    }

    private bool RefreshDue()
    {
        long last = Volatile.Read(ref _snapshotAt);
        return last == 0 || Stopwatch.GetTimestamp() - last >= _refreshTicks;
    }

    private async Task RefreshAsync(DateTimeOffset now, CancellationToken ct)
    {
        try
        {
            var fresh = new Dictionary<string, (string KeyAuthorization, DateTimeOffset Until)>(StringComparer.Ordinal);
            foreach (var row in await _config.GetAcmeRenewalsAsync(ct).ConfigureAwait(false))
            {
                foreach (var (key, value) in Parse(row.ChallengeStateJson, now))
                {
                    fresh[key] = value;
                }
            }

            _snapshot = fresh;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The store is down: answer what this process knows. A failed validation is retried with a new order anyway.
            _log.Write(MtaLogLevel.Warning, "acme", $"the HTTP-01 challenge tokens could not be read from the store ({ex.Message})", ex);
        }

        Volatile.Write(ref _snapshotAt, Math.Max(1, Stopwatch.GetTimestamp()));
    }

    private sealed record Entry(string T, string K, long U);

    private sealed record State(List<Entry>? Http01);

    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    internal static string Serialize(Dictionary<string, (string KeyAuthorization, DateTimeOffset Until)> tokens) =>
        JsonSerializer.Serialize(new State([.. tokens.Select(t => new Entry(t.Key, t.Value.KeyAuthorization, t.Value.Until.ToUnixTimeMilliseconds()))]), Json);

    /// <summary>The tokens in a stored challenge state that have not expired; damaged or foreign text is an empty set.</summary>
    internal static Dictionary<string, (string KeyAuthorization, DateTimeOffset Until)> Parse(string? json, DateTimeOffset now)
    {
        var result = new Dictionary<string, (string KeyAuthorization, DateTimeOffset Until)>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(json))
        {
            return result;
        }

        try
        {
            if (JsonSerializer.Deserialize<State>(json, Json)?.Http01 is { } entries)
            {
                foreach (var e in entries)
                {
                    var until = DateTimeOffset.FromUnixTimeMilliseconds(e.U);
                    if (e.T is { Length: > 0 } && e.K is { Length: > 0 } && until > now)
                    {
                        result[e.T] = (e.K, until);
                    }
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or ArgumentOutOfRangeException)
        {
            result.Clear();
        }

        return result;
    }
}
