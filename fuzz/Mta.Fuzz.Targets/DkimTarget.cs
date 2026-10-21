using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;

namespace Mta.Fuzz;

/// <summary>
/// The DKIM verifier over a whole message (header table, DKIM-Signature tag-value parser, canonicalization, body hash, header hash,
/// RSA verification) and the DKIM key record parser. DNS answers every key query with one fixed valid key, so signatures that
/// parse can travel the whole path.
/// </summary>
internal static class DkimTarget
{
    // A test-only public key, generated at start: no private key is stored anywhere, and the seeds carry a fake b= value, so
    // verification ends in "signature did not verify" after exercising the complete path.
    private static readonly Lazy<string> KeyTxt = new(() =>
    {
        using var rsa = RSA.Create(2048);
        return DkimKeyTools.FormatDnsTxtValue(rsa);
    });

    private static readonly FixedClock Clock = new(new DateTimeOffset(2026, 10, 12, 12, 0, 0, TimeSpan.Zero));

    public static FuzzTarget Create() => new("dkim", "DKIM verifier (DKIM-Signature tag-value parser, canonicalization, hashing) and DKIM key record parser", Run, Seeds())
    {
        Tokens = Tokens(),
        MutationIterations = 100000,
        MaxInputLength = 128 * 1024,
    };

    private static void Run(ReadOnlySpan<byte> input)
    {
        byte[] message = input.ToArray();
        var verifier = new DkimVerifier(new AnyKeyResolver(KeyTxt.Value), new DkimVerifierOptions { Clock = Clock });
        var results = verifier.VerifyAsync(message).AsTask().GetAwaiter().GetResult();
        Guard.Check(results.Count >= 1, "a message always yields at least one result");
        Guard.Check(results.Count <= 1024, "more results than headers the verifier accepts");
        foreach (var result in results)
        {
            Guard.Check(Enum.IsDefined(result.Status), "undefined verification status");
            Guard.Check(result.Reason is not null, "result without a reason");
        }

        string text = Encoding.Latin1.GetString(message, 0, Math.Min(message.Length, 20_000));
        if (DkimKeyRecord.TryParse(text, out var record, out _))
        {
            Guard.Check(record is not null, "TryParse succeeded without a record");
        }

        _ = DkimKeyTools.TryParseDnsTxtValue(text, out _, out _);
    }

    private static IReadOnlyList<byte[]> Seeds()
    {
        const string Body = "Hello,\r\n\r\nThis is the body.\r\n";
        string bodyHash = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(Body)));
        string fakeSignature = Convert.ToBase64String(new byte[256]);
        string Message(string signatureValue) =>
            "DKIM-Signature: " + signatureValue + "\r\n"
            + "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.net>\r\nSubject: Test message\r\nDate: Mon, 12 Oct 2026 12:00:00 +0000\r\nMessage-ID: <1234@example.com>\r\n\r\n" + Body;

        return
        [
            Bytes(Message($"v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; t=1791806400; x=1792411200; h=from:to:subject:date:message-id; bh={bodyHash}; b={fakeSignature}")),
            Bytes(Message($"v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=sel; l=10; h=from:from:to; i=@example.com; q=dns/txt; z=From:alice=40example.com; bh={bodyHash}; b={fakeSignature}")),
            Bytes(Message("v=1; a=rsa-sha1; d=; s=; h=; bh=; b=")),
            Bytes(Message("v=1; a=rsa-sha256;\r\n\td=example.com;\r\n s=sel; h=from : to ; bh=AAAA ; b=A A\r\n AA; ; ;;")),
            Bytes("From: a@example.com\r\n\r\nno signature\r\n"),
            Bytes("v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA; t=y:s; s=email; h=sha256; n=notes"),
            Bytes("DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=sel; h=from; bh=x; b=y\r\nDKIM-Signature: v=1\r\nDKIM-Signature:\r\n\r\n"),
        ];
    }

    private static IReadOnlyList<byte[]> Tokens() =>
    [
        Bytes("DKIM-Signature: "), Bytes("; "), Bytes("v=1"), Bytes("a=rsa-sha256"), Bytes("a=ed25519-sha256"), Bytes("c=relaxed/relaxed"), Bytes("c=simple"), Bytes("d="), Bytes("s="),
        Bytes("h="), Bytes("bh="), Bytes("b="), Bytes("l=999999999999999999999"), Bytes("l=0"), Bytes("t=0"), Bytes("x=1"), Bytes("i=@"), Bytes("z="), Bytes("q=dns/txt"),
        Bytes("\r\n\t"), Bytes("\r\n "), Bytes("\r\n\r\n"), Bytes("=3D"), Bytes("v=DKIM1"), Bytes("k=rsa"), Bytes("p="), Bytes("t=s:y"), Bytes("h=sha1:sha256"), Bytes("From:"),
    ];

    private static byte[] Bytes(string s) => Encoding.Latin1.GetBytes(s);

    private sealed class AnyKeyResolver(string keyTxt) : IDnsResolver
    {
        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default) =>
            new StaticDnsResolver().AddTxt(name, keyTxt).QueryAsync(name, type, cancellationToken);
    }
}
