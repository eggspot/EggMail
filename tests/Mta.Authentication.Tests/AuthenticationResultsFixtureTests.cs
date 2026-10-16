using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Mta.Auth;
using Mta.Auth.AuthenticationResults;
using Mta.Auth.Dmarc;
using Mta.Auth.Spf;
using Mta.Core;
using Mta.Dkim;
using Mta.Dns;

namespace Mta.Authentication.Tests;

/// <summary>
/// Fixture files (<c>Fixtures/ar/*.case</c>) describe one received message each: the connection, a DNS zone, the message (optionally signed by a fixed published test key and then edited
/// the way an intermediary would), and the Authentication-Results header that a receiver running SPF, DKIM and DMARC must write. The expected text was written by hand from RFC 7208,
/// 6376, 7489 and 8601 and then compared with the output, so a change in any of the evaluators or in the header format shows up as a readable diff of one file.
/// </summary>
public class AuthenticationResultsFixtureTests
{
    private static readonly string FixtureDirectory = Path.Combine(AppContext.BaseDirectory, "Fixtures");

    private sealed record Signing(string Domain, string Selector, string Canonicalization, string? Identity, TimeSpan? Lifetime, bool Publish);

    private sealed class Fixture
    {
        public string Name { get; init; } = "";
        public string Title { get; init; } = "";
        public Dictionary<string, string> Settings { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Zone { get; } = [];
        public List<string> Message { get; } = [];
        public List<Signing> Signings { get; } = [];
        public List<(string From, string To)> Edits { get; } = [];
        public List<string> Expect { get; } = [];
    }

    public static TheoryData<string> Cases()
    {
        var data = new TheoryData<string>();
        foreach (string name in AllNames())
        {
            data.Add(name);
        }

        return data;
    }

    private static IEnumerable<string> AllNames() =>
        Directory.GetFiles(Path.Combine(FixtureDirectory, "ar"), "*.case").Order().Select(Path.GetFileNameWithoutExtension).Select(n => n!);

    private static Fixture Load(string name)
    {
        var fixture = new Fixture { Name = name };
        List<string>? section = null;
        string kind = "head";
        foreach (string raw in File.ReadAllLines(Path.Combine(FixtureDirectory, "ar", name + ".case")))
        {
            Match header = Regex.Match(raw, @"^\[(?<kind>[a-z]+)(?<args>(\s+\S+=\S+)*)\]$");
            if (header.Success)
            {
                kind = header.Groups["kind"].Value;
                section = kind switch { "zone" => fixture.Zone, "message" => fixture.Message, "expect" => fixture.Expect, _ => null };
                if (kind == "sign")
                {
                    var args = Regex.Matches(header.Groups["args"].Value, @"(\S+)=(\S+)").ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Value);
                    fixture.Signings.Add(new Signing(args["domain"], args["selector"], args.GetValueOrDefault("canon", "relaxed/relaxed"), args.GetValueOrDefault("identity"), args.TryGetValue("lifetime", out string? life) ? TimeSpan.FromSeconds(int.Parse(life)) : null, args.GetValueOrDefault("publish", "yes") == "yes"));
                }

                continue;
            }

            switch (kind)
            {
                case "head":
                    if (raw.StartsWith('#'))
                    {
                        fixture.Settings["title"] = (fixture.Settings.GetValueOrDefault("title") + " " + raw.TrimStart('#', ' ')).Trim();
                    }
                    else if (raw.Contains(':'))
                    {
                        int colon = raw.IndexOf(':');
                        fixture.Settings[raw[..colon].Trim()] = raw[(colon + 1)..].Trim();
                    }

                    break;
                case "edit":
                    if (raw.StartsWith("replace:", StringComparison.Ordinal))
                    {
                        string[] parts = raw["replace:".Length..].Split("=>");
                        fixture.Edits.Add((Unescape(parts[0].Trim()), Unescape(parts[1].Trim())));
                    }

                    break;
                default:
                    if (raw.Length > 0 || kind == "message")
                    {
                        section?.Add(raw);
                    }

                    break;
            }
        }

        return fixture;
    }

    private static string Unescape(string text) => text.Replace("\\r\\n", "\r\n").Replace("\\t", "\t").Replace("\\s", " ");

    private static readonly RSA TestKey = LoadKey();

    private static RSA LoadKey()
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(Path.Combine(FixtureDirectory, "keys", "test-rsa-2048.key")));
        return rsa;
    }

    private sealed class FixedClock(DateTimeOffset now) : IClock
    {
        public DateTimeOffset UtcNow => now;
        public long Timestamp => now.Ticks;
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task The_receiver_writes_the_expected_authentication_results_header(string name)
    {
        var fixture = Load(name);
        var now = DateTimeOffset.Parse(fixture.Settings.GetValueOrDefault("now", "2026-10-12T12:00:00Z"), System.Globalization.CultureInfo.InvariantCulture);
        var clock = new FixedClock(now);
        var signedAt = new FixedClock(DateTimeOffset.Parse(fixture.Settings.GetValueOrDefault("signed-at", fixture.Settings.GetValueOrDefault("now", "2026-10-12T12:00:00Z")), System.Globalization.CultureInfo.InvariantCulture));

        // The world as the fixture describes it.
        string zone = string.Join('\n', fixture.Zone);
        var dns = ZoneBuilder.Build(zone);
        string message = string.Join("\r\n", fixture.Message) + "\r\n";
        foreach (var s in fixture.Signings)
        {
            if (s.Publish)
            {
                dns.AddTxt($"{s.Selector}._domainkey.{s.Domain}", DkimKeyTools.FormatDnsTxtValue(TestKey));
            }

            string[] canon = s.Canonicalization.Split('/');
            using var signer = new DkimSigner(new DkimSignerOptions
            {
                Domain = s.Domain,
                Selector = s.Selector,
                HeaderCanonicalization = Enum.Parse<DkimCanonicalization>(canon[0], true),
                BodyCanonicalization = Enum.Parse<DkimCanonicalization>(canon[1], true),
                Identity = s.Identity,
                SignatureLifetime = s.Lifetime,
                Clock = signedAt,
            }, TestKey);
            message = signer.Sign(Encoding.Latin1.GetBytes(message)) + message;
        }

        foreach (var (from, to) in fixture.Edits)
        {
            Assert.Contains(from, message);
            message = message.Replace(from, to);
        }

        // The receiver.
        var ip = IPAddress.Parse(fixture.Settings["client-ip"]);
        string helo = fixture.Settings["helo"];
        string mailFrom = fixture.Settings.GetValueOrDefault("mail-from", string.Empty);
        var spf = await new SpfEvaluator(dns).CheckSessionAsync(ip, helo, mailFrom);
        var dkim = await new DkimVerifier(dns, new DkimVerifierOptions { Clock = clock }).VerifyAsync(Encoding.Latin1.GetBytes(message));
        string fromDomain = Regex.Match(Regex.Match(message, @"(?m)^From:.*$").Value, @"@([A-Za-z0-9.\-]+)").Groups[1].Value;
        var spfDomain = string.IsNullOrEmpty(mailFrom) ? helo : mailFrom[(mailFrom.LastIndexOf('@') + 1)..];
        var dmarc = await new DmarcEvaluator(dns).EvaluateAsync(new DmarcInput(
            fromDomain,
            new SpfAuthResult(spf.Effective.Result, spfDomain),
            dkim.Where(r => r.IsPass && r.Domain is not null).Select(r => new DkimAuthResult(r.Domain!, true, r.Selector)).ToArray()));

        var builder = new AuthenticationResultsBuilder(fixture.Settings["authserv-id"]);
        builder.AddSpf(spf.Effective, string.IsNullOrEmpty(mailFrom) ? SpfIdentityKind.Helo : SpfIdentityKind.MailFrom, string.IsNullOrEmpty(mailFrom) ? helo : mailFrom);
        foreach (string fragment in DkimAuthenticationResults.FormatAll(dkim))
        {
            builder.AddDkim(fragment);
        }

        builder.AddDmarc(dmarc);
        string actual = Regex.Replace(builder.BuildFieldBody(), @"\r\n[ \t]+", " ");

        string expected = string.Join(" ", fixture.Expect).Trim();
        Assert.True(expected == actual, $"{name}\n  expected: {expected}\n  actual:   {actual}");
        // The header is a well-formed RFC 8601 field that its own parser reads back.
        Assert.True(AuthenticationResultsParser.TryParse(builder.BuildFieldBody(), out var parsed));
        Assert.Equal(fixture.Settings["authserv-id"], parsed!.AuthservId);
    }

    [Fact]
    public void There_are_at_least_a_dozen_fixtures_and_each_names_what_it_shows()
    {
        var names = AllNames().ToList();
        Assert.True(names.Count >= 12, $"only {names.Count} fixtures");
        foreach (string name in names)
        {
            Assert.False(string.IsNullOrWhiteSpace(Load(name).Settings.GetValueOrDefault("title")), name + " has no title comment");
        }
    }
}
