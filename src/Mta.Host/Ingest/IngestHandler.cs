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

        /// <summary>The request object of the session, filled again for each message (the session handles one message at a time and waits for the submission to finish).</summary>
        public SubmissionRequest Request { get; init; } = null!;
    }

    private static readonly SmtpReply AuthUnavailable = SmtpReply.Constant(454, "4.7.0", "Too many failed attempts, try again later");
    private static readonly SmtpReply StorageProblem = SmtpReply.Constant(451, "4.3.0", "Temporary problem accepting the message, try again later");
    private static readonly SmtpReply StorageFull = SmtpReply.Constant(452, "4.3.1", "Insufficient system storage, try again later");

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
            return ValueTask.FromResult(IsBounceRecipient(recipient)
                ? SmtpReplies.RecipientOk
                : SmtpReply.Create(550, "5.1.1", "No such user here"));
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

    /// <summary>
    /// The submission path is written out in this one method (no separate method for it): every asynchronous method that waits for storage is a
    /// state machine on the heap for as long as the wait lasts, and the method is the one frame between the SMTP session and the submission service.
    /// </summary>
    [System.Runtime.CompilerServices.AsyncMethodBuilder(typeof(System.Runtime.CompilerServices.PoolingAsyncValueTaskMethodBuilder<>))]
    public async ValueTask<SmtpReply> OnMessageAsync(SmtpMessage message, CancellationToken ct)
    {
        try
        {
            if (message.Session.Role == ListenerRole.Bounce)
            {
                return await HandleBounceAsync(message, ct).ConfigureAwait(false);
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

    private async ValueTask<SmtpReply> HandleBounceAsync(SmtpMessage message, CancellationToken ct)
    {
        // Always answer 250 for a verified bounce address, whatever the body holds: a rejection here would only make the remote server
        // generate more traffic, and nothing sensitive is revealed by accepting.
        if (_bounces is not null)
        {
            byte[] body = message.ToArray();
            foreach (var rcpt in message.Recipients.Where(IsBounceRecipient))
            {
                if (_bounces.IsValidBounceAddress(rcpt.LocalPart))
                {
                    await _bounces.ProcessAsync(rcpt.LocalPart, body, ct).ConfigureAwait(false);
                }
            }
        }

        return SmtpReply.Create(250, "2.0.0", "Accepted");
    }

    private bool IsBounceRecipient(EmailAddress recipient)
    {
        if (string.IsNullOrWhiteSpace(_options.BounceDomain) || !string.Equals(recipient.Domain, _options.BounceDomain, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (recipient.LocalPart.Equals("postmaster", StringComparison.OrdinalIgnoreCase) || recipient.LocalPart.Equals("abuse", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return _bounces?.IsValidBounceAddress(recipient.LocalPart) ?? false;
    }

    public void OnDisconnected(SmtpSessionContext session)
    {
    }
}
