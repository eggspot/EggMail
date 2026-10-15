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
    public string ReturnPathLabel { get; init; } = "bounce";

    public int MaxRecipientsPerMessage { get; init; } = 100;
}

/// <summary>
/// The SMTP server's application logic. Submission listeners authenticate a tenant's SMTP credential and hand messages to the
/// <see cref="SubmissionService"/>; the bounce listener accepts only verified bounce addresses and hands the message to the
/// <see cref="BounceProcessor"/>. The handler never relays: there is no path for an unauthenticated session to queue mail for delivery.
/// </summary>
public sealed class IngestHandler : ISmtpServerHandler
{
    private sealed class State
    {
        public Tenant Tenant { get; init; } = null!;
        public string RemoteAddress { get; init; } = "";   // the same for every message of the session: formatted once
        public int Recipients;
    }

    private static readonly SmtpReply AuthUnavailable = SmtpReply.Constant(454, "4.7.0", "Too many failed attempts, try again later");
    private static readonly SmtpReply StorageProblem = SmtpReply.Constant(451, "4.3.0", "Temporary problem accepting the message, try again later");

    private readonly IStorage _storage;
    private readonly SubmissionService _submission;
    private readonly AuthThrottle _throttle;
    private readonly IngestOptions _options;
    private readonly BounceProcessor? _bounces;
    private readonly Action? _onAccepted;
    private readonly IMtaLog _log;

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

    public ValueTask<SmtpReply?> OnConnectedAsync(SmtpSessionContext session, CancellationToken cancellationToken) => ValueTask.FromResult<SmtpReply?>(null);

    public async ValueTask<SmtpAuthResult> AuthenticateAsync(SmtpSessionContext session, string authorizationId, string userName, string password, CancellationToken ct)
    {
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
        session.HandlerState = new State { Tenant = tenant, RemoteAddress = ip };
        return SmtpAuthResult.Succeeded(credential!.UserName);
    }

    public ValueTask<SmtpReply> OnMailFromAsync(SmtpSessionContext session, MailFromInfo mail, CancellationToken ct)
    {
        if (session.Role == ListenerRole.Bounce)
        {
            return ValueTask.FromResult(SmtpReplies.SenderOk);
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
        if (session.Role == ListenerRole.Bounce)
        {
            return IsBounceRecipientReplyAsync(recipient, ct);
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

    private async ValueTask<SmtpReply> IsBounceRecipientReplyAsync(EmailAddress recipient, CancellationToken ct) =>
        await IsBounceRecipientAsync(recipient, ct).ConfigureAwait(false)
            ? SmtpReplies.RecipientOk
            : SmtpReply.Create(550, "5.1.1", "No such user here");

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        try
        {
            return message.Session.Role == ListenerRole.Bounce
                ? await HandleBounceAsync(message, ct).ConfigureAwait(false)
                : await HandleSubmissionAsync(message, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.Write(MtaLogLevel.Error, "ingest", "message could not be accepted", ex);
            return StorageProblem;
        }
    }

    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    private async ValueTask<SmtpReply> HandleSubmissionAsync(SmtpMessage message, CancellationToken ct)
    {
        if (message.Session.HandlerState is not State state)
        {
            return SmtpReply.Create(530, "5.7.0", "Authentication required");
        }

        var result = await _submission.SubmitAsync(new SubmissionRequest
        {
            Tenant = state.Tenant,
            Source = MessageSource.Smtp,
            EnvelopeFrom = message.Sender,
            Recipients = message.Recipients,
            // The message memory is valid for the duration of this call, which is all the submission needs (it makes its own copy of the stored message).
            Message = message.Body.IsSingleSegment ? message.Body.First : message.ToArray(),
            ReceivedHeader = message.ReceivedHeader,
            RemoteAddress = state.RemoteAddress,
            Authenticated = message.Session.AuthenticatedUser,
        }, ct).ConfigureAwait(false);

        switch (result.Status)
        {
            case SubmissionStatus.Accepted:
            case SubmissionStatus.Duplicate:
                _onAccepted?.Invoke();
                return SmtpReply.Create(250, "2.0.0", string.Create(10 + 32, result.MessageId, static (span, id) =>
                {
                    "Queued as ".CopyTo(span);
                    id.TryFormat(span[10..], out _, "N");
                }));
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

    private async ValueTask<SmtpReply> HandleBounceAsync(SmtpMessage message, CancellationToken ct)
    {
        // Always answer 250 for a verified bounce address, whatever the body holds: a rejection here would only make the remote server
        // generate more traffic, and nothing sensitive is revealed by accepting.
        if (_bounces is not null)
        {
            byte[] body = message.ToArray();
            foreach (var rcpt in message.Recipients)
            {
                if (_bounces.IsValidBounceAddress(rcpt.LocalPart) && await IsBounceRecipientAsync(rcpt, ct).ConfigureAwait(false))
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
    private async ValueTask<bool> IsBounceRecipientAsync(EmailAddress recipient, CancellationToken ct)
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

        return (_bounces?.IsValidBounceAddress(recipient.LocalPart) ?? false) && await IsVerifiedReturnPathHostAsync(recipient.Domain, ct).ConfigureAwait(false);
    }

    /// <summary><c>bounce.example.com</c> is the return-path host of the registered domain <c>example.com</c> when that domain's return-path CNAME has been verified.</summary>
    private async ValueTask<bool> IsVerifiedReturnPathHostAsync(string host, CancellationToken ct)
    {
        string prefix = _options.ReturnPathLabel + ".";
        if (!host.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || host.Length == prefix.Length)
        {
            return false;
        }

        DomainRecord? domain = await _storage.Config.FindDomainByNameAsync(host[prefix.Length..], ct).ConfigureAwait(false);
        return domain is { ReturnPathVerified: true, ReturnPathHost: { } returnPathHost } && string.Equals(returnPathHost, host, StringComparison.OrdinalIgnoreCase);
    }

    public void OnDisconnected(SmtpSessionContext session)
    {
    }
}
