using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;
using Mta.Dsn;
using Mta.Policy;
using Mta.Smtp.Client;
using Mta.Smtp.Protocol;
using Mta.Storage;
using Mta.Tls;
using Mta.Webhooks;
using PolicySmtpStage = Mta.Policy.SmtpStage;
using ClientSmtpStage = Mta.Smtp.Client.SmtpStage;

namespace Mta.Delivery;

/// <summary>The collaborators of a <see cref="DeliveryProcessor"/>.</summary>
public sealed class DeliveryServices
{
    public required IStorage Storage { get; init; }
    public required IClock Clock { get; init; }
    public required MxResolver Mx { get; init; }
    public required OutboundTlsPolicyResolver Tls { get; init; }
    public required TlsPolicyTable TlsPolicies { get; init; }
    public required SmtpConnectionPool Pool { get; init; }
    public required RoutePlanner Routes { get; init; }
    public required DestinationThrottle Throttle { get; init; }
    public required SendingLimits Limits { get; init; }
    public required RetrySchedule Retry { get; init; }
    public ReplyClassifier Classifier { get; init; } = ReplyClassifier.Default;
    public IDkimSignerProvider Dkim { get; init; } = NoDkimSignerProvider.Instance;
    public ISecretProtector? Secrets { get; init; }
    public VerpCodec? Verp { get; init; }
    public IMtaLog Log { get; init; } = NullMtaLog.Instance;

    /// <summary>Collects TLS-RPT data about sessions to MTA-STS / DANE domains; null disables reporting.</summary>
    public Mta.Tls.TlsRpt.TlsRptCollector? TlsReports { get; init; }
}

/// <summary>
/// Delivers one group of claimed deliveries that share a message and a recipient domain in a single SMTP transaction, then records
/// the per-recipient results. Never throws for delivery problems: every failure becomes a recorded outcome. Safe to run many groups concurrently.
/// </summary>
public sealed class DeliveryProcessor
{
    private const string Source = "delivery";

    private readonly DeliveryServices _s;
    private readonly DeliveryOptions _options;
    private readonly DsnService? _dsn;

    public DeliveryProcessor(DeliveryServices services, DeliveryOptions options, DsnService? dsn = null)
    {
        _s = services ?? throw new ArgumentNullException(nameof(services));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        options.Validate();
        _dsn = dsn;
    }

    /// <summary>Processes a group; all items must share <see cref="ClaimedDelivery.MessageId"/> and <see cref="ClaimedDelivery.RecipientDomain"/>.</summary>
    public async Task ProcessAsync(IReadOnlyList<ClaimedDelivery> group, CancellationToken cancellationToken)
    {
        if (group.Count == 0)
        {
            return;
        }

        long started = Stopwatch.GetTimestamp();
        for (int offset = 0; offset < group.Count; offset += _options.MaxRecipientsPerTransaction)
        {
            int count = Math.Min(_options.MaxRecipientsPerTransaction, group.Count - offset);
            var slice = new ClaimedDelivery[count];
            for (int i = 0; i < count; i++)
            {
                slice[i] = group[offset + i];
            }

            await ProcessTransactionAsync(slice, cancellationToken).ConfigureAwait(false);
        }

        DeliveryMetrics.GroupDuration.Record(Stopwatch.GetElapsedTime(started).TotalSeconds);
    }

    private async Task ProcessTransactionAsync(ClaimedDelivery[] group, CancellationToken ct)
    {
        var results = new List<Result>(group.Length);
        try
        {
            await ProcessTransactionCoreAsync(group, results, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Quiesce or shutdown: give back whatever has no recorded result yet, unchanged.
            var done = results.Select(r => r.Delivery.DeliveryId).ToHashSet();
            var now = _s.Clock.UtcNow;
            results.AddRange(group.Where(d => !done.Contains(d.DeliveryId)).Select(d => Aborted(d, now, mayHaveBeenSent: false)));
            await RecordAsync(results, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task ProcessTransactionCoreAsync(ClaimedDelivery[] group, List<Result> results, CancellationToken ct)
    {
        var first = group[0];
        var now = _s.Clock.UtcNow;

        var pending = new List<ClaimedDelivery>(group.Length);
        foreach (var d in group)
        {
            if (d.ExpiresAt <= now)
            {
                results.Add(Terminal(d, DeliveryOutcome.Expired, now, null, "delivery lifetime exceeded before an attempt could be made"));
            }
            else if (await _s.Storage.Config.IsSuppressedAsync(d.TenantId, d.Recipient.ToString(), ct).ConfigureAwait(false))
            {
                results.Add(Terminal(d, DeliveryOutcome.Suppressed, now, null, "recipient is on the suppression list"));
            }
            else
            {
                pending.Add(d);
            }
        }

        if (pending.Count > 0)
        {
            await AttemptAsync(first, pending, results, ct).ConfigureAwait(false);
        }

        Trace($"group {first.MessageId:N}/{first.RecipientDomain}: {results.Count} result(s), reporting bounces");
        await ReportBouncesAsync(results, ct).ConfigureAwait(false);
        Trace($"group {first.MessageId:N}/{first.RecipientDomain}: recording");
        await RecordAsync(results, CancellationToken.None).ConfigureAwait(false);
        Trace($"group {first.MessageId:N}/{first.RecipientDomain}: recorded");
    }

    private async Task AttemptAsync(ClaimedDelivery first, List<ClaimedDelivery> pending, List<Result> results, CancellationToken ct)
    {
        var now = _s.Clock.UtcNow;
        byte[]? raw = await _s.Storage.Deliveries.GetRawAsync(first.MessageId, ct).ConfigureAwait(false);
        if (raw is null)
        {
            foreach (var d in pending)
            {
                results.Add(Terminal(d, DeliveryOutcome.Failed, now, SmtpReply.Create(554, "5.3.0", "message data is no longer available"), "message data is no longer available"));
            }

            return;
        }

        var decision = _s.Limits.TryReserve(first.TenantId, first.SendingDomain, pending.Count);
        if (!decision.IsAllowed)
        {
            DateTimeOffset until = decision.Kind == SendingDecisionKind.Deferred
                ? decision.DeferredUntil ?? now.AddMinutes(1)
                : now.AddHours(1);
            Hold(pending, results, now, until, "held by sending limit: " + (decision.Reason ?? "limit"));
            return;
        }

        var tr = _s.Throttle.TryAcquire(new ThrottleKey(first.RecipientDomain));
        if (!tr.Acquired)
        {
            _s.Limits.Release(first.TenantId, first.SendingDomain, pending.Count, decision.At);
            var wait = tr.RetryAfter < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : tr.RetryAfter;
            Hold(pending, results, now, now + wait + TimeSpan.FromMilliseconds(Random.Shared.Next(0, 1000)), "held by destination throttle: " + tr.Denial);
            return;
        }

        byte[]? rented = null;
        try
        {
            using var lease = tr.Lease!;
            ReadOnlyMemory<byte> message;
            DkimSigner? signer = null;
            try
            {
                signer = await _s.Dkim.GetSignerAsync(first.SendingDomain ?? string.Empty, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _s.Log.Write(MtaLogLevel.Warning, Source, $"DKIM key unavailable for {first.SendingDomain}; sending unsigned", ex);
            }

            if (signer is null)
            {
                message = raw;
            }
            else
            {
                var signature = signer.SignToBytes(raw);
                rented = ArrayPool<byte>.Shared.Rent(signature.Length + raw.Length);
                signature.Span.CopyTo(rented);
                raw.CopyTo(rented.AsSpan(signature.Length));
                message = rented.AsMemory(0, signature.Length + raw.Length);
            }

            var envelope = new SmtpEnvelope(await ChooseEnvelopeFromAsync(first, now, ct).ConfigureAwait(false), pending.Select(d => d.Recipient).ToArray(), pending.Any(d => d.Recipient.IsInternational) || first.EnvelopeFrom.IsInternational, EightBit: false);
            var attempt = await RunRoutesAsync(first, envelope, message, ct).ConfigureAwait(false);
            Interpret(pending, attempt, results);

            lease.Report(attempt.Route switch
            {
                RouteAttemptResult.Delivered => ThrottleSignal.Success,
                RouteAttemptResult.ConnectTimeout or RouteAttemptResult.ConnectRefused => ThrottleSignal.ConnectionFailure,
                _ => results.Any(r => r.Class == DeliveryClass.TransientThrottle) ? ThrottleSignal.Throttled : ThrottleSignal.Success,
            });

            int undelivered = results.Count(r => r.Attempt.Outcome != DeliveryOutcome.Delivered && pending.Contains(r.Delivery));
            if (undelivered > 0)
            {
                _s.Limits.Release(first.TenantId, first.SendingDomain, undelivered, decision.At);
            }
        }
        finally
        {
            if (rented is not null)
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }
    }

    // ---------------------------------------------------------------- envelope

    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, (Guid Id, long ExpiresAt)> _domainIds = new(StringComparer.OrdinalIgnoreCase);

    private async ValueTask<EmailAddress> ChooseEnvelopeFromAsync(ClaimedDelivery d, DateTimeOffset now, CancellationToken ct)
    {
        if (_s.Verp is null || string.IsNullOrWhiteSpace(_options.BounceDomain) || d.EnvelopeFrom.IsNull || d.Source == MessageSource.Bounce)
        {
            return d.EnvelopeFrom;
        }

        // The token carries the sending domain's id so a bounce can be attributed without a lookup of the message.
        Guid domainId = await FindDomainIdAsync(d.SendingDomain, ct).ConfigureAwait(false);
        string address = _s.Verp.CreateAddress(d.TenantId, domainId, _options.BounceDomain!, now);
        return EmailAddress.TryParse(address, allowUtf8: false, out var parsed) ? parsed : d.EnvelopeFrom;
    }

    private async ValueTask<Guid> FindDomainIdAsync(string? sendingDomain, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(sendingDomain))
        {
            return Guid.Empty;
        }

        long now = _s.Clock.Timestamp;
        if (_domainIds.TryGetValue(sendingDomain, out var cached) && now < cached.ExpiresAt)
        {
            return cached.Id;
        }

        var record = await _s.Storage.Config.FindDomainByNameAsync(sendingDomain, ct).ConfigureAwait(false);
        Guid id = record?.Id ?? Guid.Empty;
        _domainIds[sendingDomain] = (id, now + 60 * Stopwatch.Frequency);
        return id;
    }

    // ---------------------------------------------------------------- routes

    private sealed class AttemptResult
    {
        public RouteAttemptResult Route { get; set; }
        public SmtpSendResult? Send { get; set; }
        public SmtpReply? Reply { get; set; }
        public ClientSmtpStage Stage { get; set; }
        public string? Error { get; set; }
        public string? MxHost { get; set; }
        public string? RouteName { get; set; }
        public SmtpTlsSession? Tls { get; set; }
        public TlsPolicyDecision? Decision { get; set; }
        public bool EndOfDataSent { get; set; }
        public TimeSpan Duration { get; set; }
        public DateTimeOffset? HoldUntil { get; set; }
        public bool Aborted { get; set; }
        public TlsFailure? TlsFailure { get; set; }
        public RemoteCertificateValidator? Validator { get; set; }
        public string? ReceivingIp { get; set; }
        public bool WasConnected { get; set; }
        public bool Connected => Route is not (RouteAttemptResult.ConnectTimeout or RouteAttemptResult.ConnectRefused);
    }

    private async Task<AttemptResult> RunRoutesAsync(ClaimedDelivery first, SmtpEnvelope envelope, ReadOnlyMemory<byte> message, CancellationToken ct)
    {
        var plan = _s.Routes.Plan(first.RecipientDomain);
        if (plan.IsEmpty)
        {
            return new AttemptResult
            {
                Route = RouteAttemptResult.ConnectRefused,
                Reply = SmtpReply.Create(451, "4.4.1", "no usable delivery route (circuit breakers open)"),
                Error = "no usable delivery route",
                HoldUntil = plan.RetryNotBefore ?? _s.Clock.UtcNow.AddMinutes(5),
            };
        }

        AttemptResult? last = null;
        int i = 0;
        while (i < plan.Steps.Count)
        {
            var step = plan.Steps[i];
            if (!_s.Routes.TryBegin(step, out _))
            {
                i++;
                continue;
            }

            var result = step.IsDirect
                ? await TryDirectAsync(first, envelope, message, ct).ConfigureAwait(false)
                : await TryRelayAsync(first, step.Relay!, envelope, message, ct).ConfigureAwait(false);
            result.RouteName = step.Name;
            _s.Routes.ReportAttempt(step, result.Route);
            last = result;

            var decision = _s.Routes.Decide(plan, i, result.Route);
            if (decision.Action == RouteAction.TryNextRoute)
            {
                i = decision.NextStepIndex;
                continue;
            }

            break;
        }

        return last ?? new AttemptResult
        {
            Route = RouteAttemptResult.ConnectRefused,
            Reply = SmtpReply.Create(451, "4.4.1", "all delivery routes are unavailable"),
            Error = "all delivery routes are unavailable",
            HoldUntil = _s.Clock.UtcNow.AddMinutes(5),
        };
    }

    private async Task<AttemptResult> TryDirectAsync(ClaimedDelivery first, SmtpEnvelope envelope, ReadOnlyMemory<byte> message, CancellationToken ct)
    {
        var mx = await _s.Mx.ResolveAsync(first.RecipientDomain, ct).ConfigureAwait(false);
        switch (mx.Status)
        {
            case MxResolutionStatus.NullMx:
                return Synthetic(RouteAttemptResult.PermanentReply, 556, "5.1.10", "domain does not accept mail (null MX)");
            case MxResolutionStatus.NoMailHost:
            case MxResolutionStatus.NonExistentDomain:
                return Synthetic(RouteAttemptResult.PermanentReply, 550, "5.1.2", mx.Detail ?? "domain has no mail host");
            case MxResolutionStatus.TempFail:
                return Synthetic(RouteAttemptResult.TemporaryReply, 451, "4.4.3", mx.Detail ?? "temporary DNS failure resolving the mail host");
        }

        var domainTls = await _s.Tls.ResolveDomainAsync(first.RecipientDomain, _s.TlsPolicies.For(first.RecipientDomain), ct).ConfigureAwait(false);
        AttemptResult? lastFailure = null;
        int hosts = 0;
        foreach (var exchanger in mx.Exchangers)
        {
            if (hosts >= _options.MaxMxHostsPerAttempt)
            {
                break;
            }

            if (!_s.Routes.TryBeginMxHost(exchanger.Host, out _))
            {
                continue;
            }

            hosts++;
            var decision = await _s.Tls.ResolveForMxAsync(domainTls, exchanger.Host, mx.MxAuthenticated, _options.RemotePort, ct).ConfigureAwait(false);
            if (decision.IsBlocked)
            {
                TlsReportRecorder.RecordBlocked(_s.TlsReports, decision, sendingIp: null);
                lastFailure = new AttemptResult
                {
                    Route = RouteAttemptResult.TlsPolicyFailure,
                    Reply = SmtpReply.Create(451, "4.7.5", "TLS policy forbids delivery via " + exchanger.Host + ": " + decision.BlockedReason),
                    Error = decision.BlockedReason,
                    MxHost = exchanger.Host,
                    Decision = decision,
                };
                continue;
            }

            int tried = 0;
            foreach (var address in exchanger.Addresses)
            {
                if (tried++ >= _options.MaxAddressesPerHost)
                {
                    break;
                }

                var target = new SmtpRemoteTarget
                {
                    Host = exchanger.Host,
                    Address = address,
                    Port = _options.RemotePort,
                    Tls = BuildTlsPolicy(decision, exchanger.Host, out var validator),
                };
                var result = await SendOnceAsync(target, envelope, message, ct).ConfigureAwait(false);
                result.MxHost = exchanger.Host;
                result.Decision = decision;
                result.Validator = validator;
                result.ReceivingIp = address.ToString();
                ReportTls(first.RecipientDomain, decision, result);
                if (result.Route is RouteAttemptResult.ConnectTimeout or RouteAttemptResult.ConnectRefused)
                {
                    _s.Routes.ReportMxHost(exchanger.Host, result.Route);
                    lastFailure = result;
                    continue;
                }

                if (result.Route == RouteAttemptResult.TlsPolicyFailure || result.Stage == ClientSmtpStage.Banner)
                {
                    // Another MX host (or address) may well accept; remember this failure in case none does.
                    _s.Routes.ReportMxHost(exchanger.Host, RouteAttemptResult.TemporaryReply);
                    lastFailure = result;
                    continue;
                }

                _s.Routes.ReportMxHost(exchanger.Host, result.Route);
                return result;
            }
        }

        return lastFailure ?? Synthetic(RouteAttemptResult.ConnectRefused, 451, "4.4.1", "no mail host is currently reachable");
    }

    private void ReportTls(string recipientDomain, TlsPolicyDecision decision, AttemptResult result)
    {
        if (_s.TlsReports is null || result.Route is RouteAttemptResult.ConnectTimeout or RouteAttemptResult.ConnectRefused || result.Aborted)
        {
            return;
        }

        // A reply before STARTTLS (for example a refusing banner) is not a TLS result either.
        if (result.TlsFailure is null && result.Tls is null)
        {
            return;
        }

        TlsReportRecorder.RecordSession(_s.TlsReports, decision, result.ReceivingIp, sendingIp: null, result.TlsFailure, result.Validator?.Outcome, result.Tls?.Used ?? false);
    }

    private async Task<AttemptResult> TryRelayAsync(ClaimedDelivery first, RelayRouteRecord relay, SmtpEnvelope envelope, ReadOnlyMemory<byte> message, CancellationToken ct)
    {
        var addresses = await _s.Mx.ResolveHostAsync(relay.Host, ct).ConfigureAwait(false);
        if (addresses.Addresses.Count == 0)
        {
            return Synthetic(RouteAttemptResult.ConnectRefused, 451, "4.4.1", $"relay {relay.Name}: host {relay.Host} does not resolve");
        }

        SmtpCredentials? credentials = null;
        if (!string.IsNullOrEmpty(relay.UserName) && relay.PasswordProtected is { Length: > 0 } protectedPassword && _s.Secrets is not null)
        {
            byte[] plain = _s.Secrets.Unprotect(protectedPassword, SecretPurposes.RelayPassword);
            credentials = new SmtpCredentials { UserName = relay.UserName, Password = System.Text.Encoding.UTF8.GetString(plain) };
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain);
        }

        var tls = relay.TlsMode.ToLowerInvariant() switch
        {
            "none" => SmtpTlsPolicy.Disabled,
            "implicit" => new SmtpTlsPolicy { Mode = SmtpTlsMode.Implicit, Require = true, TargetHost = relay.Host },
            "required" or "verify" => new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = true, TargetHost = relay.Host },
            _ => new SmtpTlsPolicy { Mode = SmtpTlsMode.StartTls, Require = false, TargetHost = relay.Host },
        };

        AttemptResult? lastFailure = null;
        foreach (var address in addresses.Addresses.Take(_options.MaxAddressesPerHost))
        {
            var target = new SmtpRemoteTarget { Host = relay.Host, Address = address, Port = relay.Port, Tls = tls, Credentials = credentials };
            var result = await SendOnceAsync(target, envelope, message, ct).ConfigureAwait(false);
            result.MxHost = relay.Host;
            if (result.Route is RouteAttemptResult.ConnectTimeout or RouteAttemptResult.ConnectRefused)
            {
                lastFailure = result;
                continue;
            }

            return result;
        }

        return lastFailure!;
    }

    private static SmtpTlsPolicy BuildTlsPolicy(TlsPolicyDecision decision, string mxHost, out RemoteCertificateValidator? validator)
    {
        validator = null;
        if (!decision.AttemptTls)
        {
            return SmtpTlsPolicy.Disabled;
        }

        validator = new RemoteCertificateValidator(decision);
        return new SmtpTlsPolicy
        {
            Mode = SmtpTlsMode.StartTls,
            Require = decision.RequireTls,
            TargetHost = string.IsNullOrEmpty(decision.ExpectedHostname) ? mxHost : decision.ExpectedHostname,
            Protocols = decision.AllowedProtocols,
            ValidationCallback = validator.Callback,
        };
    }

    private async Task<AttemptResult> SendOnceAsync(SmtpRemoteTarget target, SmtpEnvelope envelope, ReadOnlyMemory<byte> message, CancellationToken ct)
    {
        long started = Stopwatch.GetTimestamp();
        PooledConnection? pooled = null;
        long seq = Interlocked.Increment(ref _attemptSequence);
        Trace($"#{seq} connect {target.Host} [{target.Address}]:{target.Port}");
        try
        {
            pooled = await _s.Pool.RentAsync(target, ct).ConfigureAwait(false);
            var tlsSession = pooled.Connection.TlsSession;
            Trace($"#{seq} send {envelope.Recipients.Count} recipient(s) via {target.Host}");
            try
            {
                var send = await pooled.Connection.SendAsync(envelope, message, ct).ConfigureAwait(false);
                Trace($"#{seq} sent via {target.Host}: delivered={send.Delivered} stage={send.Stage} endOfData={send.EndOfDataSent}");
                return new AttemptResult
                {
                    Route = Bucket(send),
                    Send = send,
                    Tls = pooled.Connection.TlsSession,
                    Duration = Stopwatch.GetElapsedTime(started),
                    EndOfDataSent = send.EndOfDataSent,
                    Stage = send.Stage,
                };
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                pooled.Discard();
                return new AttemptResult { Route = RouteAttemptResult.ConnectionDropped, Aborted = true, WasConnected = true, Tls = tlsSession, Stage = ClientSmtpStage.Data, Duration = Stopwatch.GetElapsedTime(started) };
            }
            catch (SmtpConnectionException ex)
            {
                Trace($"#{seq} connection failed at {ex.Stage}: {ex.Message}");
                pooled.Discard();
                return Dropped(ex, tlsSession, started);
            }
            catch (Exception ex) when (ex is IOException or SocketException or SmtpProtocolException or ObjectDisposedException)
            {
                pooled.Discard();
                return new AttemptResult
                {
                    Route = RouteAttemptResult.ConnectionDropped,
                    Reply = SmtpReply.Create(421, "4.4.2", "connection lost: " + ex.Message),
                    Error = ex.Message,
                    Tls = tlsSession,
                    Stage = ClientSmtpStage.Data,
                    Duration = Stopwatch.GetElapsedTime(started),
                };
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new AttemptResult { Route = RouteAttemptResult.ConnectionDropped, Aborted = true, Stage = ClientSmtpStage.Connect, Duration = Stopwatch.GetElapsedTime(started) };
        }
        catch (SmtpTlsException ex)
        {
            return new AttemptResult
            {
                TlsFailure = ex.Failure,
                Route = RouteAttemptResult.TlsPolicyFailure,
                Reply = SmtpReply.Create(451, "4.7.5", "TLS negotiation failed: " + ex.Message),
                Error = ex.Message,
                Tls = ex.Session,
                Stage = ClientSmtpStage.StartTls,
                Duration = Stopwatch.GetElapsedTime(started),
            };
        }
        catch (SmtpGreetingRejectedException ex)
        {
            return new AttemptResult
            {
                Route = ex.Reply.IsPermanent ? RouteAttemptResult.PermanentReply : RouteAttemptResult.TemporaryReply,
                Reply = ex.Reply,
                Error = ex.Message,
                Stage = ex.Stage == ClientSmtpStage.Banner ? ClientSmtpStage.Banner : ex.Stage,
                Duration = Stopwatch.GetElapsedTime(started),
            };
        }
        catch (SmtpConnectionException ex)
        {
            return Dropped(ex, null, started);
        }
        catch (Exception ex) when (ex is SocketException or IOException or SmtpClientException or TimeoutException)
        {
            return new AttemptResult
            {
                Route = ex is TimeoutException ? RouteAttemptResult.ConnectTimeout : RouteAttemptResult.ConnectRefused,
                Reply = SmtpReply.Create(421, "4.4.1", "connection failed: " + ex.Message),
                Error = ex.Message,
                Stage = ClientSmtpStage.Connect,
                Duration = Stopwatch.GetElapsedTime(started),
            };
        }
        finally
        {
            if (pooled is not null)
            {
                await pooled.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private long _attemptSequence;

    private void Trace(string message)
    {
        if (_s.Log.IsEnabled(MtaLogLevel.Debug))
        {
            _s.Log.Write(MtaLogLevel.Debug, Source, message);
        }
    }

    private static AttemptResult Dropped(SmtpConnectionException ex, SmtpTlsSession? tls, long started)
    {
        bool beforeSession = ex.Stage is ClientSmtpStage.Connect;
        var route = beforeSession
            ? (ex.TimedOut ? RouteAttemptResult.ConnectTimeout : RouteAttemptResult.ConnectRefused)
            : RouteAttemptResult.ConnectionDropped;
        return new AttemptResult
        {
            Route = route,
            Reply = SmtpReply.Create(421, "4.4.2", (ex.TimedOut ? "timed out: " : "connection lost: ") + ex.Message),
            Error = ex.Message,
            Tls = tls,
            Stage = ex.Stage,
            EndOfDataSent = ex.EndOfDataSent,
            Duration = Stopwatch.GetElapsedTime(started),
        };
    }

    private static AttemptResult Synthetic(RouteAttemptResult route, int code, string enhanced, string text) => new()
    {
        Route = route,
        Reply = SmtpReply.Create(code, enhanced, text),
        Error = text,
        Stage = ClientSmtpStage.Connect,
    };

    private static RouteAttemptResult Bucket(SmtpSendResult send)
    {
        if (send.Delivered)
        {
            return RouteAttemptResult.Delivered;
        }

        if (send.LocalFailure != LocalFailure.None || send.SenderRejection is { IsPermanent: true } || send.DataRejection is { IsPermanent: true } || send.FinalReply is { IsPermanent: true })
        {
            return RouteAttemptResult.PermanentReply;
        }

        if (send.Recipients.Count > 0 && send.Recipients.All(r => r.Reply.IsPermanent))
        {
            return RouteAttemptResult.PermanentReply;
        }

        return RouteAttemptResult.TemporaryReply;
    }

    // ---------------------------------------------------------------- interpretation

    private sealed class Result
    {
        public required ClaimedDelivery Delivery { get; init; }
        public required DeliveryAttempt Attempt { get; init; }
        public DeliveryClass? Class { get; init; }
        public SmtpReply? Reply { get; init; }
    }

    private void Interpret(List<ClaimedDelivery> pending, AttemptResult a, List<Result> results)
    {
        var now = _s.Clock.UtcNow;
        if (a.HoldUntil is { } hold)
        {
            Hold(pending, results, now, hold, a.Error ?? "no route available");
            return;
        }

        if (a.Aborted)
        {
            foreach (var d in pending)
            {
                results.Add(Aborted(d, now, a.WasConnected));
            }

            return;
        }

        var tls = ToTlsInfo(a);
        var send = a.Send;
        foreach (var d in pending)
        {
            SmtpReply reply;
            PolicySmtpStage stage;
            bool delivered = false;
            if (send is null)
            {
                reply = a.Reply ?? SmtpReply.Create(451, "4.4.0", a.Error ?? "delivery failed");
                stage = ToPolicyStage(a.Stage);
            }
            else if (send.LocalFailure != LocalFailure.None)
            {
                reply = LocalFailureReply(send.LocalFailure);
                stage = PolicySmtpStage.MailFrom;
            }
            else if (send.SenderRejection is { } senderRejection)
            {
                reply = senderRejection;
                stage = PolicySmtpStage.MailFrom;
            }
            else
            {
                var rcpt = send.Recipients.FirstOrDefault(r => r.Address.Equals(d.Recipient));
                if (rcpt is not null && !rcpt.Accepted)
                {
                    reply = rcpt.Reply;
                    stage = PolicySmtpStage.RcptTo;
                }
                else if (send.DataRejection is { } dataRejection)
                {
                    reply = dataRejection;
                    stage = PolicySmtpStage.Data;
                }
                else if (send.FinalReply is { } final)
                {
                    reply = final;
                    stage = PolicySmtpStage.EndOfData;
                    delivered = final.IsPositiveCompletion && rcpt is not null;
                }
                else
                {
                    // Accepted for the transaction but the final answer never arrived: connection problem after (maybe) sending the data.
                    reply = a.Reply ?? SmtpReply.Create(451, "4.4.2", "no final reply from the server");
                    stage = PolicySmtpStage.EndOfData;
                }
            }

            results.Add(delivered
                ? Delivered(d, now, reply, a, tls)
                : Classified(d, now, reply, stage, a, tls));
        }
    }

    private Result Delivered(ClaimedDelivery d, DateTimeOffset now, SmtpReply reply, AttemptResult a, TlsInfo? tls) => new()
    {
        Delivery = d,
        Class = DeliveryClass.Delivered,
        Reply = reply,
        Attempt = Build(d, new DeliveryAttempt
        {
            DeliveryId = d.DeliveryId,
            Outcome = DeliveryOutcome.Delivered,
            At = now,
            SmtpCode = reply.Code,
            EnhancedCode = reply.EnhancedCode,
            Message = Text(reply),
            MxHost = a.MxHost,
            Route = a.RouteName,
            Tls = tls,
            Duration = a.Duration,
            PossibleDuplicate = d.PossibleDuplicate,
        }),
    };

    private Result Classified(ClaimedDelivery d, DateTimeOffset now, SmtpReply reply, PolicySmtpStage stage, AttemptResult a, TlsInfo? tls)
    {
        var remote = new RemoteReply(reply.Code, reply.EnhancedCode, string.Join(' ', reply.Lines));
        DeliveryClass cls = _s.Classifier.Classify(remote, stage).Class;
        if (cls == DeliveryClass.Delivered)
        {
            // A positive reply that did not complete the transaction cannot be a delivery; treat it as a temporary protocol problem.
            cls = DeliveryClass.Transient;
        }

        bool permanent = cls.IsPermanentFailure() || (cls == DeliveryClass.SoftBounceMailboxFull && !_options.RetryMailboxFull);
        DeliveryOutcome outcome;
        DateTimeOffset? next = null;
        string message = Text(reply);
        if (permanent)
        {
            outcome = DeliveryOutcome.Failed;
        }
        else
        {
            var decision = _s.Retry.NextAttemptAt(d.Attempt + 1, now, d.ExpiresAt, cls, remote);
            if (decision.Expire)
            {
                outcome = DeliveryOutcome.Expired;
                message = $"delivery expired after {d.Attempt + 1} attempt(s); last response: {message}";
            }
            else
            {
                outcome = DeliveryOutcome.Deferred;
                next = decision.NextAttemptAt;
            }
        }

        bool maybeSent = a.EndOfDataSent && a.Route == RouteAttemptResult.ConnectionDropped;
        return new Result
        {
            Delivery = d,
            Class = cls,
            Reply = reply,
            Attempt = Build(d, new DeliveryAttempt
            {
                DeliveryId = d.DeliveryId,
                Outcome = outcome,
                At = now,
                SmtpCode = reply.Code,
                EnhancedCode = reply.EnhancedCode,
                Message = message,
                MxHost = a.MxHost,
                Route = a.RouteName,
                Tls = tls,
                Duration = a.Duration,
                NextAttemptAt = next,
                PossibleDuplicate = d.PossibleDuplicate || maybeSent,
                Suppress = outcome == DeliveryOutcome.Failed && cls.ShouldSuppressRecipient() ? SuppressionReason.HardBounce : null,
            }),
        };
    }

    private static Result Terminal(ClaimedDelivery d, DeliveryOutcome outcome, DateTimeOffset now, SmtpReply? reply, string message) => new()
    {
        Delivery = d,
        Reply = reply,
        Attempt = Build(d, new DeliveryAttempt
        {
            DeliveryId = d.DeliveryId,
            Outcome = outcome,
            At = now,
            SmtpCode = reply?.Code,
            EnhancedCode = reply?.EnhancedCode,
            Message = message,
            PossibleDuplicate = d.PossibleDuplicate,
        }),
    };

    private static Result Aborted(ClaimedDelivery d, DateTimeOffset now, bool mayHaveBeenSent) => new()
    {
        Delivery = d,
        Attempt = new DeliveryAttempt
        {
            DeliveryId = d.DeliveryId,
            Outcome = DeliveryOutcome.AbortedBySwitch,
            At = now,
            Message = "attempt aborted; the delivery is requeued unchanged",
            PossibleDuplicate = d.PossibleDuplicate || mayHaveBeenSent,
            CountAttempt = false,
        },
    };

    private void Hold(List<ClaimedDelivery> pending, List<Result> results, DateTimeOffset now, DateTimeOffset until, string reason)
    {
        DeliveryMetrics.Held.Add(pending.Count);
        foreach (var d in pending)
        {
            results.Add(new Result
            {
                Delivery = d,
                Attempt = new DeliveryAttempt
                {
                    DeliveryId = d.DeliveryId,
                    Outcome = DeliveryOutcome.Deferred,
                    At = now,
                    Message = reason,
                    NextAttemptAt = until,
                    CountAttempt = false,
                },
            });
        }
    }

    private static DeliveryAttempt Build(ClaimedDelivery d, DeliveryAttempt attempt)
    {
        var draft = WebhookEventFactory.ForAttempt(d, attempt);
        return draft is null ? attempt : Clone(attempt, [draft]);
    }

    private static DeliveryAttempt Clone(DeliveryAttempt a, IReadOnlyList<WebhookEventDraft> events) => new()
    {
        DeliveryId = a.DeliveryId,
        Outcome = a.Outcome,
        At = a.At,
        SmtpCode = a.SmtpCode,
        EnhancedCode = a.EnhancedCode,
        Message = a.Message,
        MxHost = a.MxHost,
        Route = a.Route,
        Tls = a.Tls,
        Duration = a.Duration,
        NextAttemptAt = a.NextAttemptAt,
        PossibleDuplicate = a.PossibleDuplicate,
        Suppress = a.Suppress,
        WebhookEvents = events,
        CountAttempt = a.CountAttempt,
    };

    private static string Text(SmtpReply reply)
    {
        string text = string.Join(' ', reply.Lines);
        string prefix = reply.EnhancedCode is null ? reply.Code.ToString() : reply.Code + " " + reply.EnhancedCode;
        string full = prefix + " " + text;
        return full.Length <= 1000 ? full : full[..1000];
    }

    private static SmtpReply LocalFailureReply(LocalFailure failure) => failure switch
    {
        LocalFailure.MessageTooLarge => SmtpReply.Create(552, "5.3.4", "message exceeds the size limit of the receiving server"),
        LocalFailure.Smtputf8NotSupported => SmtpReply.Create(553, "5.6.7", "the receiving server does not support internationalized addresses (SMTPUTF8)"),
        LocalFailure.EightBitNotSupported => SmtpReply.Create(554, "5.6.1", "the receiving server does not accept 8-bit content"),
        _ => SmtpReply.Create(554, "5.6.0", "message could not be transmitted"),
    };

    private static PolicySmtpStage ToPolicyStage(ClientSmtpStage stage) => stage switch
    {
        ClientSmtpStage.Connect => PolicySmtpStage.Connect,
        ClientSmtpStage.Banner or ClientSmtpStage.Ehlo or ClientSmtpStage.StartTls or ClientSmtpStage.Auth => PolicySmtpStage.Handshake,
        ClientSmtpStage.MailFrom => PolicySmtpStage.MailFrom,
        ClientSmtpStage.RcptTo => PolicySmtpStage.RcptTo,
        ClientSmtpStage.Data => PolicySmtpStage.Data,
        _ => PolicySmtpStage.EndOfData,
    };

    private static TlsInfo? ToTlsInfo(AttemptResult a)
    {
        var s = a.Tls;
        if (s is null)
        {
            return null;
        }

        return new TlsInfo(
            s.Used,
            s.Protocol,
            s.CipherSuite,
            s.PeerSubject,
            s.PeerIssuer,
            s.PeerSha256,
            s.PolicyErrors == System.Net.Security.SslPolicyErrors.None ? null : s.PolicyErrors.ToString(),
            s.Verified,
            a.Decision?.Kind.ToString(),
            null,
            s.StartTlsAdvertised,
            s.PlaintextFallback);
    }

    // ---------------------------------------------------------------- recording

    private async Task RecordAsync(List<Result> results, CancellationToken ct)
    {
        foreach (var r in results)
        {
            DeliveryMetrics.Attempts.Add(1, new KeyValuePair<string, object?>("outcome", r.Attempt.Outcome.ToString().ToLowerInvariant()));
        }

        await Task.WhenAll(results.Select(r => _s.Storage.Deliveries.RecordAttemptAsync(r.Attempt, ct).AsTask())).ConfigureAwait(false);
    }

    private async Task ReportBouncesAsync(List<Result> results, CancellationToken ct)
    {
        if (_dsn is null)
        {
            return;
        }

        var failed = results.Where(r => r.Attempt.Outcome is DeliveryOutcome.Failed or DeliveryOutcome.Expired).ToList();
        if (failed.Count == 0)
        {
            return;
        }

        try
        {
            await _dsn.ReportAsync(failed.Select(r => new BounceItem(r.Delivery, r.Attempt)).ToList(), ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _s.Log.Write(MtaLogLevel.Error, Source, "could not generate a bounce message", ex);
        }
    }

    /// <summary>Records the expiry of deliveries that ran out of lifetime while waiting (no connection attempt is made).</summary>
    public async Task ExpireAsync(IReadOnlyList<ClaimedDelivery> expired, CancellationToken ct)
    {
        var now = _s.Clock.UtcNow;
        var results = expired
            .Select(d => Terminal(d, DeliveryOutcome.Expired, now, null, $"delivery expired after {d.Attempt} attempt(s)" + (d.LastError is null ? string.Empty : "; last error: " + d.LastError)))
            .ToList();
        await ReportBouncesAsync(results, ct).ConfigureAwait(false);
        await RecordAsync(results, CancellationToken.None).ConfigureAwait(false);
    }
}
