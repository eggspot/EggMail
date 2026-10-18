using Mta.Core;

namespace Mta.Storage.Logic;

/// <summary>What <see cref="InboundRules.Effective"/> returns: the limits the receive path and the retention job apply to one domain.</summary>
/// <param name="MaxMessageBytes">Largest message.</param>
/// <param name="MaxMessagesPerMinute">Messages per minute for the domain.</param>
/// <param name="MaxMessagesPerMinutePerRemote">Messages per minute per client address.</param>
/// <param name="MaxStoredBytes">Stored body bytes for the domain; 0 unlimited.</param>
/// <param name="RetentionDays">Days kept; 0 forever.</param>
public readonly record struct InboundEffectiveLimits(long MaxMessageBytes, int MaxMessagesPerMinute, int MaxMessagesPerMinutePerRemote, long MaxStoredBytes, int RetentionDays);

/// <summary>One problem found by the inbound validators: the request member (<c>forwardTo[1]</c>, <c>localPart</c>) and a sentence for the caller.</summary>
public readonly record struct InboundValidationError(string Field, string Message);

/// <summary>
/// The rules of inbound mail that must be the same everywhere (the receive path, the API, the dashboard, the tests): which route handles a
/// recipient, what a valid route or settings object is, the initial state of a message and the retention a domain gets (design section 11).
/// Pure functions, no I/O.
/// </summary>
public static class InboundRules
{
    /// <summary>Routes per domain (an API limit, <c>Api:MaxInboundRoutesPerDomain</c> may lower it).</summary>
    public const int MaxRoutesPerDomain = 100;

    public const int MaxForwardTargets = 10;
    public const int MaxLocalPartLength = 64;

    /// <summary>The most messages one search page holds, on every backend and in the API.</summary>
    public const int MaxPageSize = 200;

    /// <summary>The most messages one erasure or retention write deletes.</summary>
    public const int MaxBatchRows = 100;

    /// <summary>The most stored body bytes one erasure or retention write deletes (a few large messages are a batch of their own).</summary>
    public const long MaxBatchBytes = 64L << 20;
    public const int MaxWildcards = 3;
    public const int MaxRouteNameLength = 100;
    public const int MaxSubjectLength = 256;
    public const int MaxRetentionDays = 36_500;
    public const long MaxConfiguredMessageBytes = 1L << 30;

    /// <summary>A forwarded message that has been forwarded this many times by this server is not forwarded again (the signed hop marker, design section 11.7).</summary>
    public const int MaxForwardHops = 3;

    /// <summary>How long the idempotency key of a forward is remembered: longer than the retry ladder and any manual retry (decision 95).</summary>
    public static readonly TimeSpan ForwardKeyLifetime = TimeSpan.FromDays(366);

    /// <summary>The idempotency key of the forward of one inbound message (independent of how often the action is retried).</summary>
    public static string ForwardKey(Guid inboundMessageId) => "inbound:" + inboundMessageId.ToString("N");

    /// <summary>
    /// Whether <paramref name="localPart"/> is <c>postmaster</c> (any case): RFC 5321 section 4.5.1 requires a domain that receives mail to accept it, so the receive path accepts and
    /// stores it as an implicit delivery when no route matches (an explicit route for it wins).
    /// </summary>
    public static bool IsPostmaster(string localPart) => string.Equals(localPart, "postmaster", StringComparison.OrdinalIgnoreCase);
    private const string LocalPartSpecials = "!#$%&'+-/=?^_`{|}~.";

    /// <summary>
    /// The route that handles <paramref name="localPart"/>: among the enabled routes that match, the one with the lowest <see cref="InboundRouteRecord.Order"/>
    /// (ties: the lowest <see cref="InboundRouteRecord.Id"/>). Null when none matches, which the receive path answers with <c>550 5.1.1</c> at RCPT time.
    /// The list need not be sorted.
    /// </summary>
    public static InboundRouteRecord? MatchRoute(IReadOnlyList<InboundRouteRecord> routes, string localPart)
    {
        InboundRouteRecord? best = null;
        for (int i = 0; i < routes.Count; i++)
        {
            InboundRouteRecord route = routes[i];
            if (!route.Enabled || !Matches(route, localPart))
            {
                continue;
            }

            if (best is null || route.Order < best.Order || (route.Order == best.Order && route.Id.CompareTo(best.Id) < 0))
            {
                best = route;
            }
        }

        return best;
    }

    /// <summary>
    /// Whether <paramref name="route"/> handles <paramref name="localPart"/>, ignoring <see cref="InboundRouteRecord.Enabled"/>. Local parts are compared ignoring case
    /// (RFC 5321 allows a case-sensitive local part, but no mail system relies on two mailboxes differing in case). With
    /// <see cref="InboundRouteRecord.PlusAddressing"/> a local part containing <c>+</c> is also compared without everything from the first <c>+</c> on
    /// (<c>support+billing</c> is tried as itself and as <c>support</c>); a local part that starts with <c>+</c> has no such base.
    /// </summary>
    public static bool Matches(InboundRouteRecord route, string localPart)
    {
        if (route.MatchKind == InboundMatchKind.CatchAll)
        {
            return true;
        }

        if (localPart.Length == 0 || route.LocalPart is not { Length: > 0 } pattern)
        {
            return false;
        }

        if (MatchesOne(route.MatchKind, pattern, localPart))
        {
            return true;
        }

        if (route.PlusAddressing)
        {
            int plus = localPart.IndexOf('+', StringComparison.Ordinal);
            if (plus > 0)
            {
                return MatchesOne(route.MatchKind, pattern, localPart.AsSpan(0, plus));
            }
        }

        return false;
    }

    private static bool MatchesOne(InboundMatchKind kind, string pattern, ReadOnlySpan<char> localPart) =>
        kind == InboundMatchKind.Address
            ? localPart.Equals(pattern, StringComparison.OrdinalIgnoreCase)
            : GlobMatch(pattern, localPart);

    // '*' matches any run of characters (including none); everything else matches itself ignoring case. Linear in the input for a
    // bounded number of stars (MaxWildcards): the classic two-pointer match with one backtrack point.
    private static bool GlobMatch(ReadOnlySpan<char> pattern, ReadOnlySpan<char> text)
    {
        int p = 0, t = 0, starP = -1, starT = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && pattern[p] == '*')
            {
                starP = p++;
                starT = t;
            }
            else if (p < pattern.Length && char.ToLowerInvariant(pattern[p]) == char.ToLowerInvariant(text[t]))
            {
                p++;
                t++;
            }
            else if (starP >= 0)
            {
                p = starP + 1;
                t = ++starT;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*')
        {
            p++;
        }

        return p == pattern.Length;
    }

    /// <summary>
    /// The limits a domain really has: its own value, else the operator's, and never above the operator's ceiling (a tenant can only lower a limit; the operator may have lowered a ceiling
    /// after the domain stored its value). A stored-bytes limit of 0 is unlimited, so "the lower of two" never takes the 0 while the other side is finite.
    /// </summary>
    public static InboundEffectiveLimits Effective(InboundDomainSettings settings, InboundCeilings ceilings, int serverRetentionDays) => new(
        Math.Min(settings.MaxMessageBytes ?? ceilings.MaxMessageBytes, ceilings.MaxMessageBytes),
        Math.Min(settings.MaxMessagesPerMinute ?? ceilings.MaxMessagesPerMinute, ceilings.MaxMessagesPerMinute),
        Math.Min(settings.MaxMessagesPerMinutePerRemote ?? ceilings.MaxMessagesPerMinutePerRemote, ceilings.MaxMessagesPerMinutePerRemote),
        settings.MaxStoredBytes is not { } stored ? ceilings.MaxStoredBytesPerDomain
            : ceilings.MaxStoredBytesPerDomain == 0 ? stored
            : stored == 0 ? ceilings.MaxStoredBytesPerDomain
            : Math.Min(stored, ceilings.MaxStoredBytesPerDomain),
        ResolveRetentionDays(settings.RetentionDays, serverRetentionDays, ceilings.MaxRetentionDays));

    /// <summary>Whether a query narrows the tenant's mail at all (a bulk erasure refuses a query that does not). The paging members do not count.</summary>
    public static bool HasFilter(InboundMessageQuery query) =>
        query.DomainId is not null || !string.IsNullOrWhiteSpace(query.Recipient) || !string.IsNullOrWhiteSpace(query.Sender) || !string.IsNullOrEmpty(query.SubjectContains)
        || query.RouteId is not null || query.ActionKind is not null || query.ActionState is not null || query.Dmarc is not null || query.DmarcFlagged is not null
        || query.From is not null || query.To is not null;

    /// <summary>The action state a new message starts in (see <see cref="InboundMessageDraft"/>).</summary>
    public static InboundActionState InitialActionState(InboundActionKind kind) =>
        kind is InboundActionKind.Webhook or InboundActionKind.Forward ? InboundActionState.Pending : InboundActionState.Done;

    /// <summary>Whether a message with this action kind keeps its body when it is stored (discard does not).</summary>
    public static bool StoresBody(InboundActionKind kind) => kind != InboundActionKind.Discard;

    /// <summary>
    /// The retention in days a domain gets: its own value, else the server default; 0 means keep forever. A negative server default (a configuration
    /// the validator refuses) is treated as the built-in 7 days rather than as unlimited. <paramref name="ceilingDays"/> is <c>Inbound:MaxRetentionDays</c> (0: none).
    /// </summary>
    public static int ResolveRetentionDays(int? domainRetentionDays, int serverDefaultDays, int ceilingDays = 0)
    {
        int days = domainRetentionDays ?? (serverDefaultDays < 0 ? 7 : serverDefaultDays);

        // The operator's ceiling: a longer value is cut to it and "forever" becomes it (a ceiling of 0 means there is none).
        return ceilingDays > 0 && (days == 0 || days > ceilingDays) ? ceilingDays : days;
    }

    /// <summary>The oldest receive time a message may have to be kept, or null when the retention is unlimited.</summary>
    public static DateTimeOffset? RetentionCutoff(DateTimeOffset now, int retentionDays) =>
        retentionDays <= 0 ? null : now.AddDays(-retentionDays);

    /// <summary>
    /// Validates the settings a caller wants to store. The domain being verified is the caller's check (it needs the domain). With <paramref name="ceilings"/> a value above the operator's
    /// limit is refused (a tenant can only lower a limit): a size or rate above the ceiling, a stored-bytes limit above the ceiling or "unlimited" under a finite ceiling, a retention above
    /// the retention ceiling or "forever" under it.
    /// </summary>
    public static IReadOnlyList<InboundValidationError> ValidateSettings(InboundDomainSettings settings, InboundCeilings? ceilings = null, IReadOnlyCollection<string>? ceilingFields = null)
    {
        // A caller that changes some members passes their names: a member it does not touch is not checked against the ceilings (the operator may have lowered one since it was stored).
        bool Checks(string field) => ceilingFields is null || ceilingFields.Contains(field);
        var errors = new List<InboundValidationError>();
        if (!Enum.IsDefined(settings.DmarcAction))
        {
            errors.Add(new("dmarcAction", "Unknown DMARC action."));
        }

        if (settings.MaxMessageBytes is { } size && (size < 1024 || size > MaxConfiguredMessageBytes))
        {
            errors.Add(new("maxMessageBytes", $"Must be between 1024 and {MaxConfiguredMessageBytes} bytes."));
        }

        if (settings.MaxMessagesPerMinute is { } perMinute && (perMinute < 1 || perMinute > 100_000))
        {
            errors.Add(new("maxMessagesPerMinute", "Must be between 1 and 100000."));
        }

        if (settings.MaxMessagesPerMinutePerRemote is { } perRemote && (perRemote < 1 || perRemote > 10_000))
        {
            errors.Add(new("maxMessagesPerMinutePerRemote", "Must be between 1 and 10000."));
        }

        if (settings.MaxStoredBytes is { } stored && stored != 0 && (stored < (1L << 20) || stored > (1L << 50)))
        {
            errors.Add(new("maxStoredBytes", "Must be 0 (unlimited) or between 1 MiB and 1 PiB."));
        }

        if (settings.RetentionDays is { } days && (days < 0 || days > MaxRetentionDays))
        {
            errors.Add(new("retentionDays", $"Must be between 0 (keep forever) and {MaxRetentionDays}."));
        }

        if (ceilings is not null && errors.Count == 0)
        {
            if (Checks("maxMessageBytes") && settings.MaxMessageBytes > ceilings.MaxMessageBytes)
            {
                errors.Add(new("maxMessageBytes", $"At most {ceilings.MaxMessageBytes} bytes on this server (Inbound:MaxMessageSize)."));
            }

            if (Checks("maxMessagesPerMinute") && settings.MaxMessagesPerMinute > ceilings.MaxMessagesPerMinute)
            {
                errors.Add(new("maxMessagesPerMinute", $"At most {ceilings.MaxMessagesPerMinute} on this server (Inbound:MaxMessagesPerMinute)."));
            }

            if (Checks("maxMessagesPerMinutePerRemote") && settings.MaxMessagesPerMinutePerRemote > ceilings.MaxMessagesPerMinutePerRemote)
            {
                errors.Add(new("maxMessagesPerMinutePerRemote", $"At most {ceilings.MaxMessagesPerMinutePerRemote} on this server (Inbound:MaxMessagesPerMinutePerRemote)."));
            }

            if (Checks("maxStoredBytes") && settings.MaxStoredBytes is { } storedLimit && ceilings.MaxStoredBytesPerDomain > 0 && (storedLimit == 0 || storedLimit > ceilings.MaxStoredBytesPerDomain))
            {
                errors.Add(new("maxStoredBytes", $"At most {ceilings.MaxStoredBytesPerDomain} bytes on this server (Inbound:MaxStoredBytesPerDomain), and not unlimited."));
            }

            if (Checks("retentionDays") && settings.RetentionDays is { } keepDays && ceilings.MaxRetentionDays > 0 && (keepDays == 0 || keepDays > ceilings.MaxRetentionDays))
            {
                errors.Add(new("retentionDays", $"At most {ceilings.MaxRetentionDays} days on this server (Inbound:MaxRetentionDays), and not forever."));
            }
        }

        return errors;
    }

    /// <summary>
    /// Validates a route as a caller wants to store it: the match (a catch-all has no local part, an address has one without <c>*</c>, a wildcard has one
    /// with 1 to <see cref="MaxWildcards"/> stars and something besides stars), the action (a webhook names an endpoint, a forward has 1 to
    /// <see cref="MaxForwardTargets"/> distinct valid addresses, store and discard carry no target). That the webhook endpoint exists and is the tenant's is the caller's check.
    /// </summary>
    public static IReadOnlyList<InboundValidationError> ValidateRoute(InboundRouteRecord route, string? domainName = null, IReadOnlySet<string>? localInboundDomains = null)
    {
        var errors = new List<InboundValidationError>();
        if (route.Name.Length > MaxRouteNameLength || ContainsControl(route.Name))
        {
            errors.Add(new("name", $"At most {MaxRouteNameLength} characters, no control characters."));
        }

        if (!Enum.IsDefined(route.MatchKind))
        {
            errors.Add(new("matchKind", "Unknown match kind."));
        }
        else
        {
            ValidateMatch(route, errors);
        }

        if (!Enum.IsDefined(route.ActionKind))
        {
            errors.Add(new("action", "Unknown action."));
        }
        else
        {
            ValidateAction(route, errors, domainName, localInboundDomains);
        }

        return errors;
    }

    private static void ValidateMatch(InboundRouteRecord route, List<InboundValidationError> errors)
    {
        string? local = route.LocalPart;
        if (route.MatchKind == InboundMatchKind.CatchAll)
        {
            if (local is not null)
            {
                errors.Add(new("localPart", "A catch-all route has no local part."));
            }

            if (route.PlusAddressing)
            {
                errors.Add(new("plusAddressing", "Plus addressing does not apply to a catch-all route."));
            }

            return;
        }

        if (string.IsNullOrEmpty(local))
        {
            errors.Add(new("localPart", "Required."));
            return;
        }

        if (local.Length > MaxLocalPartLength)
        {
            errors.Add(new("localPart", $"At most {MaxLocalPartLength} characters."));
        }

        if (!string.Equals(local, local.ToLowerInvariant(), StringComparison.Ordinal))
        {
            errors.Add(new("localPart", "Must be lower case (matching ignores case)."));
        }

        int stars = 0;
        foreach (char c in local)
        {
            if (c == '*')
            {
                stars++;
            }
            else if (c < 128 && !char.IsAsciiLetterOrDigit(c) && !LocalPartSpecials.Contains(c, StringComparison.Ordinal))
            {
                errors.Add(new("localPart", $"The character '{c}' is not allowed in a local part."));
                break;
            }
        }

        if (route.MatchKind == InboundMatchKind.Address && stars > 0)
        {
            errors.Add(new("localPart", "An address route has no '*'; use a wildcard route."));
        }

        if (route.MatchKind == InboundMatchKind.Wildcard)
        {
            if (stars == 0)
            {
                errors.Add(new("localPart", "A wildcard route needs a '*'; use an address route for an exact match."));
            }
            else if (stars > MaxWildcards)
            {
                errors.Add(new("localPart", $"At most {MaxWildcards} '*'."));
            }
            else if (local.Replace("*", string.Empty, StringComparison.Ordinal).Length == 0)
            {
                errors.Add(new("localPart", "A pattern of only '*' is a catch-all route."));
            }
        }
    }

    private static void ValidateAction(InboundRouteRecord route, List<InboundValidationError> errors, string? domainName, IReadOnlySet<string>? localInboundDomains)
    {
        switch (route.ActionKind)
        {
            case InboundActionKind.Webhook:
                if (route.WebhookEndpointId is null || route.WebhookEndpointId == Guid.Empty)
                {
                    errors.Add(new("webhookEndpointId", "Required for a webhook action."));
                }

                if (!Enum.IsDefined(route.WebhookFormat))
                {
                    errors.Add(new("webhookFormat", "Unknown webhook format."));
                }

                if (route.ForwardTo.Count > 0)
                {
                    errors.Add(new("forwardTo", "Only a forward action has targets."));
                }

                break;

            case InboundActionKind.Forward:
                if (route.WebhookEndpointId is not null)
                {
                    errors.Add(new("webhookEndpointId", "Only a webhook action has an endpoint."));
                }

                if (route.ForwardTo.Count is 0 or > MaxForwardTargets)
                {
                    errors.Add(new("forwardTo", $"Between 1 and {MaxForwardTargets} addresses."));
                    break;
                }

                string? ownDomain = domainName is null ? null : ALabel(domainName);
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < route.ForwardTo.Count; i++)
                {
                    string field = $"forwardTo[{i}]";
                    if (!EmailAddress.TryParse(route.ForwardTo[i], allowUtf8: true, out EmailAddress address) || address.IsNull)
                    {
                        errors.Add(new(field, "Not a valid address."));
                    }
                    else if (!seen.Add(address.LocalPart + "@" + ALabel(address.Domain)))
                    {
                        errors.Add(new(field, "Listed twice."));
                    }
                    else if (ownDomain is not null && string.Equals(ALabel(address.Domain), ownDomain, StringComparison.OrdinalIgnoreCase))
                    {
                        errors.Add(new(field, "A route cannot forward to its own domain: the forward would come straight back."));
                    }
                    else if (localInboundDomains is not null && localInboundDomains.Contains(ALabel(address.Domain)))
                    {
                        errors.Add(new(field, "This server receives mail for that domain: the forward would loop. Use an address at another mail provider."));
                    }
                }

                break;

            default:
                if (route.WebhookEndpointId is not null)
                {
                    errors.Add(new("webhookEndpointId", "Only a webhook action has an endpoint."));
                }

                if (route.ForwardTo.Count > 0)
                {
                    errors.Add(new("forwardTo", "Only a forward action has targets."));
                }

                break;
        }
    }

    // Domains are compared in A-label form, so "bücher.example" and "xn--bcher-kva.example" are the same domain (a name that cannot be converted compares as itself).
    private static readonly System.Globalization.IdnMapping Idn = new() { UseStd3AsciiRules = false, AllowUnassigned = false };

    /// <summary>
    /// The domains of a forward route's targets in A-label form, lower-case, without duplicates: what a caller looks up to find which of them this server receives for, before it passes
    /// that set to <see cref="ValidateRoute"/>. (The loop check has one implementation: the validator; callers only supply the facts it cannot read.)
    /// </summary>
    public static IReadOnlyList<string> ForwardTargetDomains(InboundRouteRecord route)
    {
        var domains = new List<string>();
        foreach (string target in route.ForwardTo)
        {
            if (EmailAddress.TryParse(target, allowUtf8: true, out EmailAddress address) && !address.IsNull && ALabel(address.Domain) is { } domain && !domains.Contains(domain))
            {
                domains.Add(domain);
            }
        }

        return domains;
    }

    /// <summary>A domain name in A-label form, lower-case, without a trailing dot (the form domains are compared in everywhere).</summary>
    public static string ALabel(string domain)
    {
        string trimmed = domain.TrimEnd('.');
        try
        {
            return Idn.GetAscii(trimmed).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return trimmed.ToLowerInvariant();
        }
    }

    private static bool ContainsControl(string text)
    {
        foreach (char c in text)
        {
            if (char.IsControl(c))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>The lower-case words the API, the headers and the logs use for the inbound enums, in one place.</summary>
public static class InboundNames
{
    public static string Of(InboundVerdict verdict) => verdict switch
    {
        InboundVerdict.None => "none",
        InboundVerdict.Pass => "pass",
        InboundVerdict.Fail => "fail",
        InboundVerdict.SoftFail => "softfail",
        InboundVerdict.Neutral => "neutral",
        InboundVerdict.TempError => "temperror",
        InboundVerdict.PermError => "permerror",
        InboundVerdict.Policy => "policy",
        _ => "none",
    };

    public static bool TryParse(string? text, out InboundVerdict verdict)
    {
        verdict = text switch
        {
            "none" => InboundVerdict.None,
            "pass" => InboundVerdict.Pass,
            "fail" => InboundVerdict.Fail,
            "softfail" => InboundVerdict.SoftFail,
            "neutral" => InboundVerdict.Neutral,
            "temperror" => InboundVerdict.TempError,
            "permerror" => InboundVerdict.PermError,
            "policy" => InboundVerdict.Policy,
            _ => (InboundVerdict)255,
        };
        return verdict != (InboundVerdict)255;
    }

    public static string Of(InboundDmarcAction action) => action switch
    {
        InboundDmarcAction.Flag => "flag",
        InboundDmarcAction.Reject => "reject",
        _ => "record_only",
    };

    public static bool TryParse(string? text, out InboundDmarcAction action)
    {
        action = text switch
        {
            "record_only" => InboundDmarcAction.RecordOnly,
            "flag" => InboundDmarcAction.Flag,
            "reject" => InboundDmarcAction.Reject,
            _ => (InboundDmarcAction)255,
        };
        return action != (InboundDmarcAction)255;
    }

    public static string Of(InboundActionKind kind) => kind switch
    {
        InboundActionKind.Webhook => "webhook",
        InboundActionKind.Forward => "forward",
        InboundActionKind.Store => "store",
        _ => "discard",
    };

    public static bool TryParse(string? text, out InboundActionKind kind)
    {
        kind = text switch
        {
            "webhook" => InboundActionKind.Webhook,
            "forward" => InboundActionKind.Forward,
            "store" => InboundActionKind.Store,
            "discard" => InboundActionKind.Discard,
            _ => (InboundActionKind)255,
        };
        return kind != (InboundActionKind)255;
    }

    public static string Of(InboundMatchKind kind) => kind switch
    {
        InboundMatchKind.Address => "address",
        InboundMatchKind.Wildcard => "wildcard",
        _ => "catch_all",
    };

    public static bool TryParse(string? text, out InboundMatchKind kind)
    {
        kind = text switch
        {
            "catch_all" => InboundMatchKind.CatchAll,
            "address" => InboundMatchKind.Address,
            "wildcard" => InboundMatchKind.Wildcard,
            _ => (InboundMatchKind)255,
        };
        return kind != (InboundMatchKind)255;
    }

    public static string Of(InboundActionState state) => state switch
    {
        InboundActionState.Done => "done",
        InboundActionState.Failed => "failed",
        _ => "pending",
    };

    public static bool TryParse(string? text, out InboundActionState state)
    {
        state = text switch
        {
            "pending" => InboundActionState.Pending,
            "done" => InboundActionState.Done,
            "failed" => InboundActionState.Failed,
            _ => (InboundActionState)255,
        };
        return state != (InboundActionState)255;
    }

    public static string Of(InboundWebhookFormat format) => format == InboundWebhookFormat.RawMime ? "raw_mime" : "json";

    public static bool TryParse(string? text, out InboundWebhookFormat format)
    {
        format = text switch
        {
            "json" => InboundWebhookFormat.Json,
            "raw_mime" => InboundWebhookFormat.RawMime,
            _ => (InboundWebhookFormat)255,
        };
        return format != (InboundWebhookFormat)255;
    }
}
