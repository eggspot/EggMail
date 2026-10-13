namespace Mta.Fuzz;

/// <summary>The registry of fuzz targets, shared by the coverage-guided harness and the deterministic regression test.</summary>
public static class FuzzTargets
{
    private static readonly Lazy<IReadOnlyList<FuzzTarget>> AllTargets = new(() =>
    [
        SmtpProtocolTarget.Create(),
        SmtpSessionTarget.Create(),
        MimeTarget.Create(),
        DkimTarget.Create(),
        SpfTarget.Create(),
        DnsMessageTarget.Create(),
        DsnArfTarget.Create(),
        MtaStsTarget.Create(),
        TlsRptTarget.Create(),
        AuthHeadersTarget.Create(),
        DmarcAggregateTarget.Create(),
    ]);

    public static IReadOnlyList<FuzzTarget> All => AllTargets.Value;

    /// <summary>Runs one input through the SMTP session target and returns what the server sent back (the first byte selects the listener). For tests that the target really talks to the server.</summary>
    public static byte[] SmtpSessionTranscript(byte[] input) => SmtpSessionTarget.Exchange(input);

    public static FuzzTarget Get(string name) =>
        All.FirstOrDefault(t => string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase))
        ?? throw new ArgumentException($"unknown fuzz target '{name}'; known: {string.Join(", ", All.Select(t => t.Name))}", nameof(name));
}
