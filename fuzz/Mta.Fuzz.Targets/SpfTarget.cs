using System.Net;
using System.Text;
using Mta.Auth.Spf;
using Mta.Dns;

namespace Mta.Fuzz;

/// <summary>
/// SPF: the record parser, the macro parser and expander, and the full evaluator (which follows include/redirect/a/mx/exists through
/// a resolver that serves the fuzzed record for every TXT query, so the lookup limits are exercised too).
/// </summary>
internal static class SpfTarget
{
    public static FuzzTarget Create() => new("spf", "SPF record parser, macro expansion and evaluator", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 120000,
        MaxInputLength = 16 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        string text = Decode(input);

        if (SpfRecord.TryParse(text, 4096, out var record, out string? error))
        {
            Guard.Check(record.Text == text, "the parsed record must keep its text");
            Guard.Check(record.Directives.Count <= text.Length, "more directives than characters");
            Guard.Check(SpfRecord.TryParse(text, 4096, out var again, out _) && again.Directives.Count == record.Directives.Count, "parsing is not deterministic");
        }
        else
        {
            Guard.Check(!string.IsNullOrEmpty(error), "a refused record needs a reason");
        }

        var context = new SpfMacroContext("strong-bad@email.example.com", "email.example.com", IPAddress.Parse("192.0.2.3"), "mx.example.org");
        if (SpfMacroString.TryParse(text, SpfMacroKind.DomainSpec, out var macro, out _))
        {
            if (macro.TryExpand(context, 255, out string? expanded))
            {
                Guard.Check(expanded.Length <= 255, "macro expansion longer than the limit");
            }
        }

        _ = SpfMacroString.TryParse(text, SpfMacroKind.Explanation, out _, out _);
        _ = SpfDomainName.TryNormalizeExpanded(text, out _);

        // Evaluate: the fuzzed text is the SPF record of every domain asked about.
        var evaluator = new SpfEvaluator(new EverywhereResolver(text), new SpfOptions());
        var result = evaluator.CheckHostAsync(new SpfCheckRequest(IPAddress.Parse("192.0.2.3"), "email.example.com", "strong-bad@email.example.com", "mx.example.org")).AsTask().GetAwaiter().GetResult();
        Guard.Check(result.DnsLookupCount <= 10 + 1, $"DNS lookup limit exceeded: {result.DnsLookupCount}");
        Guard.Check(result.VoidLookupCount <= 2 + 1, $"void lookup limit exceeded: {result.VoidLookupCount}");
    }

    private static string Decode(ReadOnlySpan<byte> input) =>
        input.Length > 0 && (input[0] & 1) == 1 ? Encoding.Latin1.GetString(input) : Encoding.UTF8.GetString(input);

    private static IReadOnlyList<byte[]> Seeds() =>
        new[]
        {
            "v=spf1 mx -all",
            "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a:mail.example.com/24//64 include:_spf.example.net ~all",
            "v=spf1 a mx ptr exists:%{i}._spf.%{d2} redirect=%{l1r+-}._at_.%{o}._spf.%{d2}",
            "v=spf1 include:a.example include:b.example include:c.example include:d.example include:e.example include:f.example include:g.example include:h.example include:i.example include:j.example include:k.example -all",
            "v=spf1 exp=explain.%{d} +all",
            "v=spf1 mx:%{d}/33 a//129 ip4:1.2.3.4/33 ip4:300.1.1.1 ip6:::g/200 foo=bar exp=",
            "v=spf1 %{d}%%%_%-%{ir}.%{v}.%{d4}.%{ir2}.%{",
            "v=spf1",
            "v=spf1 redirect=example.com redirect=example.org",
            "v=spf2.0/pra mx",
        }.Select(s => Encoding.UTF8.GetBytes(s)).ToList();

    private static IReadOnlyList<byte[]> Tokens() =>
        new[]
        {
            "v=spf1 ", " include:", " redirect=", " exp=", " ip4:", " ip6:", " a:", " mx:", " ptr", " exists:", " all", " -all", " ~all", " ?all", "+", "-", "~", "?",
            "/24", "//64", "%{", "%{d}", "%{i}", "%{ir}", "%{l1r-}", "%{s}", "%{o}", "%{h}", "%{c}", "%{r}", "%{t}", "}", "%%", "%_", "%-", ".", ":", "=", "\0",
        }.Select(s => Encoding.UTF8.GetBytes(s)).ToList();

    /// <summary>Answers every TXT query with the fuzzed record and every other query with an empty, successful answer.</summary>
    private sealed class EverywhereResolver(string spfText) : IDnsResolver
    {
        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
        {
            var dns = new StaticDnsResolver();
            if (type == DnsRecordType.TXT)
            {
                dns.AddTxt(name, spfText.Length > 4000 ? spfText[..4000] : spfText);
            }
            else if (type == DnsRecordType.A)
            {
                dns.AddA(name, "192.0.2.3");
            }

            return dns.QueryAsync(name, type, cancellationToken);
        }
    }
}
