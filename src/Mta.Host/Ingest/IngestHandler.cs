using System.Buffers;
using Mta.Core;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Smtp.Protocol;
using Mta.Smtp.Server;
using Mta.Storage;

namespace Mta.Host.Ingest;

public sealed class IngestOptions
{
    /// <summary>Domain of bounce addresses; recipients on the bounce listener must be tokens at this domain (or postmaster/abuse).</summary>
    public string? BounceDomain { get; init; }

    /// <summary>First label of a sending domain's own return-path host (<c>bounce.example.com</c>); the host is accepted on the bounce listener once the domain's return-path CNAME is verified.</summary>
    public string ReturnPathLabel { get; init; } = Mta.Policy.SenderPolicy.DefaultReturnPathLabel;

    public int MaxRecipientsPerMessage { get; init; } = 100;
}

/// <summary>
/// The SMTP server's application logic. Submission listeners authenticate a tenant's SMTP credential and hand messages to the
/// <see cref="SubmissionService"/>; the bounce listener accepts only verified bounce addresses and hands the message to the
/// <see cref="BounceProcessor"/>. The handler never relays: there is no path for an unauthenticated session to queue mail for delivery.
/// </summary>
public sealed class IngestHandler : ISmtpServerHandler, IBounceNamespace
{
    private sealed class State
    {
        public Tenant Tenant { get; init; } = null!;
        public string RemoteAddress { get; init; } = "";   // the same for every message of the session: formatted once
        public int Recipients;

        /// <summary>The request object of the session, filled again for each message (the session handles one message at a time and waits for the submission to finish).</summary>
        public SubmissionRequest Request { get; init; } = null!;
    }

    private static readonly SmtpReply AuthUnavailable = SmtpReply.Constant(454, "4.7.0", "Too many failed attempts, try again later");
    private static readonly SmtpReply StorageProblem = SmtpReply.Constant(451, "4.3.0", "Temporary problem accepting the message, try again later");
    private static readonly SmtpReply StorageFull = SmtpReply.Constant(452, "4.3.1", "Insufficient system storage, try again later");

    // Answers of the return-path host lookup, for a minute: the RCPT of a bounce and its DATA both ask, and a remote server may send many bounces.
    private static readonly long HostCacheTicks = 60 * System.Diagnostics.Stopwatch.Frequency;
    private const int MaxCachedHosts = 1024;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (bool Verified, long ExpiresAt)> _returnPathHosts = new(StringComparer.OrdinalIgnoreCase);

    private readonly IStorage _storage;
    private readonly SubmissionService _submission;
    private readonly AuthThrottle _throttle;
    private readonly IngestOptions _options;
    private readonly BounceProcessor? _bounces;
    private readonly Action? _onAccepted;
    private readonly IMtaLog _log;
    private InboundReceiver? _inbound;

    public IngestHandler(IStorage storage, SubmissionService submission, AuthThrottle throttle, IngestOptions? options = null, BounceProcessor? bounces = null, Action? onAccepted = null, IMtaLog? log = null)
    {
        _storage = storage;
        _submission = submission;
        _throttle = throttle;
        _options = options ?? new IngestOptions();
        _bounces = bounces;
        _onAccepted = onAccepted;
        _log = log ?? NullMtaLog.Instance;
    }

    /// <summary>
    /// Turns the listeners of role <see cref="ListenerRole.Inbound"/> into MX receivers (design section 11). Without it such a listener behaves exactly like the bounce listener: accepting inbound mail
    /// is something that has to be wired, never a default. The receiver is built after the handler because it asks the handler which recipients are bounce addresses.
    /// </summary>
    public void UseInbound(InboundReceiver receiver) => _inbound = receiver;

    /// <summary>Whether the session is one of the inbound MX receiver (and a receiver is wired).</summary>
    private InboundReceiver? InboundOf(SmtpSessionContext session) => session.Role == ListenerRole.Inbound ? _inbound : null;

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken cancellationToken) =>
        InboundOf(session) is { } inbound ? inbound.OnConnectedAsync(session) : ValueTask.FromResult<SmtpReply?>(null);

    public void OnMessageRefused(SmtpSessionContext session, SmtpReply reply) => InboundOf(session)?.OnMessageRefused(session, reply);

    public ValueTask<SmtpReply?> OnDataStartAsync(SmtpSessionContext session, MailFromInfo mail, IReadOnlyList<EmailAddress> recipients, CancellationToken cancellationToken) =>
        InboundOf(session) is { } inbound ? inbound.OnDataStartAsync(session) : ValueTask.FromResult<SmtpReply?>(null);

    public async ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct)
    {
        if (session.Role != ListenerRole.Submission)
        {
            return SmtpAuthResult.Failed;   // the server offers no AUTH on these listeners; a handler that is asked anyway never authenticates anybody on a port-25 listener
        }

        string ip = session.RemoteEndPoint.Address.ToString();
        string userKey = "user:" + Mta.Storage.Model.ConfigMapping.NormalizeUserName(userName);   // the same key as the dashboard sign-in: one budget per account, whichever door
        var check = await _throttle.CheckAsync(ct, ip, userKey).ConfigureAwait(false);
        if (check.IsLockedOut)
        {
            return SmtpAuthResult.Rejected(AuthUnavailable);
        }

        SmtpCredential? credential;
        try
        {
            credential = await _storage.Config.FindSmtpCredentialAsync(userName, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.Write(MtaLogLevel.Error, "ingest", "credential lookup failed", ex);
            return SmtpAuthResult.Rejected(StorageProblem);
        }

        bool ok;
        if (credential is null)
        {
            PasswordHasher.VerifyDummy(password);   // same work for unknown users: no user enumeration by timing
            ok = false;
        }
        else
        {
            ok = PasswordHasher.Verify(password, credential.PasswordHash) && credential.Enabled;
        }

        var tenant = ok ? await _storage.Config.GetTenantAsync(credential!.TenantId, ct).ConfigureAwait(false) : null;
        if (tenant is not { Enabled: true })
        {
            await _throttle.RecordFailureAsync(ip, userKey).ConfigureAwait(false);
            return SmtpAuthResult.Failed;
        }

        await _throttle.RecordSuccessAsync(check, ip, userKey).ConfigureAwait(false);
        session.HandlerState = new State
        {
            Tenant = tenant,
            RemoteAddress = ip,
            Request = new SubmissionRequest { Tenant = tenant, Source = MessageSource.Smtp, EnvelopeFrom = default, Recipients = [], Message = default, RemoteAddress = ip },
        };
        return SmtpAuthResult.Succeeded(credential!.UserName);
    }

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct)
    {
        // Every role other than Submission is "not a submitter": it can never reach the submission path (AUTH, relay, sender policy).
        if (session.Role != ListenerRole.Submission)
        {
            return InboundOf(session) is { } inbound ? inbound.OnMailFromAsync(session, mail) : ValueTask.FromResult(SmtpReplies.SenderOk);
        }

        if (session.HandlerState is not State state)
        {
            return ValueTask.FromResult(SmtpReply.Create(530, "5.7.0", "Authentication required"));
        }

        state.Recipients = 0;
        return ValueTask.FromResult(SmtpReplies.SenderOk);
    }

    public ValueTask<SmtpReply> OnRcptToAsync(SmtpSessionContext session, MailFromInfo mail, EmailAddress recipient, RcptParameters parameters, CancellationToken ct)
    {
        if (session.Role != ListenerRole.Submission)
        {
            return InboundOf(session) is { } inbound ? inbound.OnRcptToAsync(session, mail, recipient, ct) : IsBounceRecipientReplyAsync(recipient, NetworkKey.Remote(session.RemoteEndPoint.Address), ct);
        }

        if (session.HandlerState is not State state)
        {
            return ValueTask.FromResult(SmtpReply.Create(530, "5.7.0", "Authentication required"));
        }

        if (++state.Recipients > _options.MaxRecipientsPerMessage)
        {
            return ValueTask.FromResult(SmtpReply.Create(452, "4.5.3", $"Too many recipients: at most {_options.MaxRecipientsPerMessage} per message"));
        }

        return ValueTask.FromResult(SmtpReplies.RecipientOk);
    }

    private async ValueTask<SmtpReply> IsBounceRecipientReplyAsync(EmailAddress recipient, string clientKey, CancellationToken ct)
    {
        try
        {
            return await IsBounceRecipientAsync(recipient, clientKey, ct).ConfigureAwait(false)
                ? SmtpReplies.RecipientOk
                : SmtpReply.Create(550, "5.1.1", "No such user here");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Only a token at a sending domain's return-path host needs the storage; a remote server that gets 451 tries again later.
            _log.Write(MtaLogLevel.Warning, "ingest", "bounce recipient could not be checked", ex);
            return StorageProblem;
        }
    }

    /// <summary>
    /// The submission path is written out in this one method (no separate method for it): every asynchronous method that waits for storage is a
    /// state machine on the heap for as long as the wait lasts, and the method is the one frame between the SMTP session and the submission service.
    /// </summary>
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        try
        {
            if (message.Session.Role != ListenerRole.Submission)
            {
                return InboundOf(message.Session) is { } inbound
                    ? await inbound.OnMessageAsync(message, ct).ConfigureAwait(false)
                    : await HandleBounceAsync(message, ct).ConfigureAwait(false);
            }

            if (message.Session.HandlerState is not State state)
            {
                return SmtpReply.Create(530, "5.7.0", "Authentication required");
            }

            var request = state.Request;
            request.EnvelopeFrom = message.Sender;
            request.Recipients = message.Recipients;
            // The message memory is valid for the duration of this call, which is all the submission needs (it makes its own copy of the stored message).
            request.Message = message.Body.IsSingleSegment ? message.Body.First : message.ToArray();
            request.ReceivedHeader = message.ReceivedHeader;
            request.Authenticated = message.Session.AuthenticatedUser;
            SubmissionResult result;
            try
            {
                // The steps of SubmitAsync, written out here: the checks and the repair run without waiting, so the only suspended frames while storage works
                // are this one and the storage's own. (A message that needs a setting loaded first, once in a few seconds, takes the ordinary path.)
                var loaded = new LoadedSettings();
                PreparedSubmission prepared = _submission.Prepare(request, ref loaded, out SubmissionLoad load, out SubmissionResult refused);
                if (load != SubmissionLoad.None)
                {
                    result = await _submission.SubmitAsync(request, ct).ConfigureAwait(false);
                }
                else if (prepared.IsFinal)
                {
                    result = refused;
                }
                else
                {
                    IntakeResult intake;
                    try
                    {
                        intake = await _submission.StoreAsync(prepared, ct).ConfigureAwait(false);
                    }
                    catch
                    {
                        _submission.Abandon(ref prepared);
                        throw;
                    }

                    result = _submission.Complete(ref prepared, intake);
                }
            }
            finally
            {
                // Nothing of the message may stay reachable through the reused request once the call is over (the memory goes back to its pool).
                request.EnvelopeFrom = default;
                request.Recipients = [];
                request.Message = default;
                request.ReceivedHeader = default;
            }

            if (result.Status is SubmissionStatus.Accepted or SubmissionStatus.Duplicate)
            {
                _onAccepted?.Invoke();
            }

            return ReplyFor(result);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (StorageFullException ex)
        {
            _log.Write(MtaLogLevel.Error, "ingest", "message could not be accepted: the disk is full", ex);
            return StorageFull;
        }
        catch (Exception ex)
        {
            _log.Write(MtaLogLevel.Error, "ingest", "message could not be accepted", ex);
            return StorageProblem;
        }
    }

    private static SmtpReply ReplyFor(SubmissionResult result)
    {
        switch (result.Status)
        {
            case SubmissionStatus.Accepted:
            case SubmissionStatus.Duplicate:
                return SmtpReply.CreateWithId(250, "2.0.0", "Queued as ", result.MessageId);
            case SubmissionStatus.Rejected:
                return SmtpReply.Create(result.Rejection!.SmtpCode, result.Rejection.EnhancedCode, result.Rejection.Message);
            case SubmissionStatus.TooLarge:
                return SmtpReply.Create(552, "5.3.4", "Message size exceeds the limit");
            default:
                return result.Rejection is { } r
                    ? SmtpReply.Create(r.SmtpCode, r.EnhancedCode, r.Message)
                    : SmtpReply.Create(554, "5.6.0", result.Detail ?? "Message cannot be accepted");
        }
    }

    ValueTask<SmtpReply> IBounceNamespace.HandleMessageAsync(SmtpMessage message, CancellationToken cancellationToken) => HandleBounceAsync(message, cancellationToken);

    /// <summary>
    /// Whether a recipient is in the bounce namespace, which the inbound classification must leave alone: the shared bounce domain and the verified return-path hosts of registered domains. Inside it only a valid
    /// signed token (or <c>postmaster</c>/<c>abuse</c> at the shared bounce domain) is accepted; anything else is <c>550 5.1.1</c> and is never an inbound recipient (decision 92, design section 11.4).
    /// </summary>
    async ValueTask<BounceRecipientClass> IBounceNamespace.ClassifyAsync(EmailAddress recipient, string clientKey, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.BounceDomain))
        {
            return BounceRecipientClass.NotBounce;
        }

        bool shared = string.Equals(recipient.Domain, _options.BounceDomain, StringComparison.OrdinalIgnoreCase);
        if (!shared)
        {
            // A caller without a valid token never causes a storage lookup: a host the cache knows as a verified return-path host is refused with the bounce answer, any other name is simply not ours.
            bool tokenValid = _bounces?.IsValidBounceAddress(recipient.LocalPart) ?? false;
            if (!await IsVerifiedReturnPathHostAsync(recipient.Domain, tokenValid, clientKey, cancellationToken).ConfigureAwait(false))
            {
                return BounceRecipientClass.NotBounce;
            }
        }

        return await IsBounceRecipientAsync(recipient, clientKey, cancellationToken).ConfigureAwait(false) ? BounceRecipientClass.Accepted : BounceRecipientClass.Refused;
    }

    private async ValueTask<SmtpReply> HandleBounceAsync(SmtpMessage message, CancellationToken ct)
    {
        // Always answer 250 for a verified bounce address, whatever the body holds: a rejection here would only make the remote server
        // generate more traffic, and nothing sensitive is revealed by accepting.
        if (_bounces is not null)
        {
            // A report is read from its head: the status part comes first, and some servers return the whole original after it. Only that much is copied and parsed.
            byte[] body = message.Body.Slice(0, Math.Min(message.Body.Length, MaxBounceHeadBytes)).ToArray();
            foreach (var rcpt in message.Recipients)
            {
                if (_bounces.IsValidBounceAddress(rcpt.LocalPart) && await IsBounceRecipientAsync(rcpt, NetworkKey.Remote(message.Session.RemoteEndPoint.Address), ct).ConfigureAwait(false))
                {
                    await _bounces.ProcessAsync(rcpt.LocalPart, body, ct).ConfigureAwait(false);
                }
            }
        }

        return SmtpReply.Create(250, "2.0.0", "Accepted");
    }

    /// <summary>
    /// A recipient the bounce listener takes: a valid signed token at the shared bounce domain (or <c>postmaster</c>/<c>abuse</c> there), or a valid
    /// token at a sending domain's own return-path host. The token check is a local HMAC, so strangers' addresses cost no storage access; only an
    /// address that carries a valid token for a host other than the shared bounce domain is looked up.
    /// </summary>
    private async ValueTask<bool> IsBounceRecipientAsync(EmailAddress recipient, string clientKey, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_options.BounceDomain))
        {
            return false;
        }

        if (string.Equals(recipient.Domain, _options.BounceDomain, StringComparison.OrdinalIgnoreCase))
        {
            if (recipient.LocalPart.Equals("postmaster", StringComparison.OrdinalIgnoreCase) || recipient.LocalPart.Equals("abuse", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return _bounces?.IsValidBounceAddress(recipient.LocalPart) ?? false;
        }

        return (_bounces?.IsValidBounceAddress(recipient.LocalPart) ?? false) && await IsVerifiedReturnPathHostAsync(recipient.Domain, tokenValid: true, clientKey, ct).ConfigureAwait(false);
    }

    /// <summary>How much of a report is parsed (the status part of a DSN comes after its human-readable text, and a server may append the whole original).</summary>
    private const int MaxBounceHeadBytes = 256 * 1024;

    // Names of the form bounce.<anything> each cost a storage lookup the first time they are asked about. Only a caller with a valid signed token can cause one (a name without a token is answered from the
    // cache or is "not ours"), and each client gets a few uncached lookups a second, with a backstop for the process: over it the caller (who holds a real token) gets a temporary failure and tries again.
    private const int MaxUncachedHostLookupsPerClientPerSecond = 10;
    private const int MaxUncachedHostLookupsPerSecond = 200;
    private const int MaxTrackedLookupClients = 4096;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (long Second, int Count)> _lookupsByClient = new(StringComparer.Ordinal);
    private long _lookupWindow;
    private int _lookupsInWindow;

    private bool TryTakeLookup(string clientKey)
    {
        long second = Environment.TickCount64 / 1000;
        if (_lookupsByClient.Count >= MaxTrackedLookupClients)
        {
            foreach (var entry in _lookupsByClient)
            {
                if (entry.Value.Second < second)
                {
                    _lookupsByClient.TryRemove(entry.Key, out _);
                }
            }

            if (_lookupsByClient.Count >= MaxTrackedLookupClients && !_lookupsByClient.ContainsKey(clientKey))
            {
                return false;
            }
        }

        // The client's own budget first: a client past it is refused without touching the process-wide count, so one client cannot use up what the others need.
        (long Second, int Count) updated = _lookupsByClient.AddOrUpdate(clientKey, (second, 1), (_, old) => old.Second == second ? (second, old.Count + 1) : (second, 1));
        if (updated.Count > MaxUncachedHostLookupsPerClientPerSecond)
        {
            return false;
        }

        if (Interlocked.Exchange(ref _lookupWindow, second) != second)
        {
            Volatile.Write(ref _lookupsInWindow, 0);
        }

        return Interlocked.Increment(ref _lookupsInWindow) <= MaxUncachedHostLookupsPerSecond;
    }

    /// <summary><c>bounce.example.com</c> is the return-path host of the registered domain <c>example.com</c> when that domain's return-path CNAME has been verified.</summary>
    private async ValueTask<bool> IsVerifiedReturnPathHostAsync(string host, bool tokenValid, string clientKey, CancellationToken ct)
    {
        string prefix = _options.ReturnPathLabel + ".";
        if (!host.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || host.Length == prefix.Length)
        {
            return false;
        }

        long now = System.Diagnostics.Stopwatch.GetTimestamp();
        if (_returnPathHosts.TryGetValue(host, out var cached) && now < cached.ExpiresAt)
        {
            return cached.Verified;
        }

        if (!tokenValid)
        {
            return false;   // no token, no lookup
        }

        if (!TryTakeLookup(clientKey))
        {
            throw new StorageUnavailableException("Too many return-path host lookups at the moment.");
        }

        DomainRecord? domain = await _storage.Config.FindDomainByNameAsync(host[prefix.Length..], ct).ConfigureAwait(false);
        bool verified = domain is { ReturnPathVerified: true, ReturnPathHost: { } returnPathHost } && string.Equals(returnPathHost, host, StringComparison.OrdinalIgnoreCase);
        if (_returnPathHosts.Count >= MaxCachedHosts)
        {
            EvictOldestHosts(now);
        }

        _returnPathHosts[host] = (verified, now + HostCacheTicks);
        return verified;
    }

    // Expired answers go first, then the ones that expire first (the oldest): never the whole table at once, which would send every host back to storage.
    private void EvictOldestHosts(long now)
    {
        foreach (var entry in _returnPathHosts)
        {
            if (now >= entry.Value.ExpiresAt)
            {
                _returnPathHosts.TryRemove(entry.Key, out _);
            }
        }

        if (_returnPathHosts.Count >= MaxCachedHosts)
        {
            foreach (string key in _returnPathHosts.OrderBy(e => e.Value.ExpiresAt).Take(MaxCachedHosts / 8).Select(e => e.Key).ToList())
            {
                _returnPathHosts.TryRemove(key, out _);
            }
        }
    }

    public void OnDisconnected(SmtpSessionContext session)
    {
    }
}
