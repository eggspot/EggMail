using Mta.Storage;
using Mta.Tls;

namespace Mta.Delivery;

/// <summary>
/// Per-destination TLS level overrides (<see cref="TlsPolicyRecord"/>): exact domain, <c>*.suffix</c> or <c>*</c>. The most specific
/// pattern wins. Reloaded from the configuration store by <see cref="Update"/>; reads are lock-free.
/// </summary>
public sealed class TlsPolicyTable
{
    private sealed record Snapshot(Dictionary<string, TlsLevel> Exact, List<(string Suffix, TlsLevel Level)> Suffixes, TlsLevel? Any);

    private volatile Snapshot _snapshot = new([], [], null);
    private readonly OutboundTlsConfiguration _default;

    public TlsPolicyTable(OutboundTlsConfiguration defaultConfiguration) => _default = defaultConfiguration;

    public void Update(IEnumerable<TlsPolicyRecord> policies)
    {
        var exact = new Dictionary<string, TlsLevel>(StringComparer.OrdinalIgnoreCase);
        var suffixes = new List<(string, TlsLevel)>();
        TlsLevel? any = null;
        foreach (var p in policies)
        {
            string pattern = p.DomainPattern.Trim().TrimEnd('.').ToLowerInvariant();
            if (pattern == "*")
            {
                any = p.Level;
            }
            else if (pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                suffixes.Add((pattern[1..], p.Level));
            }
            else if (pattern.Length > 0)
            {
                exact[pattern] = p.Level;
            }
        }

        suffixes.Sort((a, b) => b.Item1.Length.CompareTo(a.Item1.Length));
        _snapshot = new Snapshot(exact, suffixes, any);
    }

    /// <summary>The TLS configuration for a recipient domain.</summary>
    public OutboundTlsConfiguration For(string recipientDomain)
    {
        var s = _snapshot;
        string d = recipientDomain.Trim().TrimEnd('.').ToLowerInvariant();
        TlsLevel? level = null;
        if (s.Exact.TryGetValue(d, out var e))
        {
            level = e;
        }
        else
        {
            foreach (var (suffix, l) in s.Suffixes)
            {
                if (d.EndsWith(suffix, StringComparison.Ordinal))
                {
                    level = l;
                    break;
                }
            }
        }

        level ??= s.Any;
        return level is null ? _default : _default with { Level = Map(level.Value) };
    }

    private static TlsSecurityLevel Map(TlsLevel level) => level switch
    {
        TlsLevel.None => TlsSecurityLevel.None,
        TlsLevel.May => TlsSecurityLevel.May,
        TlsLevel.Encrypt => TlsSecurityLevel.Encrypt,
        _ => TlsSecurityLevel.Verify,
    };
}
