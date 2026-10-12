using Mta.Auth.Arc;
using static Mta.Auth.Tests.Arc.ArcMsg;

namespace Mta.Auth.Tests.Arc;

public class ArcRoundTripTests
{
    [Fact]
    public async Task Message_without_arc_headers_is_none()
    {
        var result = await ValidateAsync(Original());
        Assert.Equal(ArcChainStatus.None, result.Status);
        Assert.Equal(0, result.InstanceCount);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(5)]
    public async Task Chain_sealed_by_our_sealer_validates(int hops)
    {
        string message = await ChainAsync(hops);
        var result = await ValidateAsync(message);

        Assert.True(result.IsPass, result.Reason + "\n" + message);
        Assert.Equal(hops, result.InstanceCount);
        Assert.Equal(Hops.Take(hops), result.SealDomains);
        Assert.Equal(1, result.OldestPassingInstance);
    }

    [Fact]
    public async Task First_hop_writes_instance_one_with_cv_none_and_later_hops_cv_pass()
    {
        string one = await ChainAsync(1);
        Assert.Contains("ARC-Seal: i=1;", one);
        Assert.Contains("cv=none", one);
        string two = await ChainAsync(2);
        Assert.Contains("ARC-Seal: i=2;", two);
        Assert.Contains("cv=pass", two);
    }

    [Fact]
    public async Task Sealer_output_is_seal_then_message_signature_then_results_each_crlf_terminated()
    {
        using var sealer = Sealer("a.example");
        var result = sealer.Seal(Bytes(Original()), "mx.a.example; spf=pass smtp.mailfrom=alice@origin.example", new ArcChainResult(ArcChainStatus.None, "none"));

        Assert.True(result.IsSealed);
        Assert.Equal(1, result.Instance);
        Assert.Equal(ArcChainStatus.None, result.ChainValidationStatus);
        var (fields, body) = Split(result.Headers);
        Assert.Equal(string.Empty, body);
        Assert.Equal(3, fields.Count);
        Assert.StartsWith("ARC-Seal:", fields[0]);
        Assert.StartsWith("ARC-Message-Signature:", fields[1]);
        Assert.StartsWith("ARC-Authentication-Results: i=1; mx.a.example; spf=pass", fields[2]);
        Assert.EndsWith("\r\n", result.Headers);
        Assert.All(result.Headers.Split("\r\n"), line => Assert.True(line.Length <= 80, "line too long: " + line));
        Assert.Equal(result.Headers, Text(result.HeaderBytes.Span));
    }

    [Fact]
    public async Task Sealing_works_with_every_signed_header_option_and_oversigning()
    {
        var dns = DnsForAllHops();
        foreach (bool oversign in new[] { false, true })
        {
            string message = await HopAsync(Original(), "a.example", dns, oversign: oversign);
            var result = await ValidateAsync(message, dns);
            Assert.True(result.IsPass, result.Reason);
        }
    }

    [Fact]
    public async Task Oversigned_message_signature_fails_when_a_header_is_added_after_sealing()
    {
        var dns = DnsForAllHops();
        string message = await HopAsync(Original(), "a.example", dns, oversign: true);
        Assert.True((await ValidateAsync(message, dns)).IsPass);

        var injected = await ValidateAsync("Subject: injected\r\n" + message, dns);
        Assert.Equal(ArcFailure.MessageSignatureMismatch, injected.Failure);

        // Without oversigning an extra Subject above the signed one is not covered.
        string plain = await HopAsync(Original(), "a.example", dns, oversign: false);
        Assert.True((await ValidateAsync("Subject: injected\r\n" + plain, dns)).IsPass);
    }

    [Fact]
    public async Task A_hop_may_modify_the_message_if_it_seals_after_the_change()
    {
        var dns = DnsForAllHops();
        string first = await HopAsync(Original(), "a.example", dns);
        string second = await HopAsync(first, "b.example", dns, m => ReplaceFirst(m, "Subject: Test message", "Subject: [list] Test message"));

        var result = await ValidateAsync(second, dns);
        Assert.True(result.IsPass, result.Reason);
        Assert.Equal(2, result.InstanceCount);
        // The first signature no longer verifies (the subject changed), the second does.
        Assert.Equal(2, result.OldestPassingInstance);
    }

    [Fact]
    public async Task Body_change_by_a_hop_moves_the_oldest_passing_instance()
    {
        var dns = DnsForAllHops();
        string m = await HopAsync(Original(), "a.example", dns);
        m = await HopAsync(m, "b.example", dns);
        m = await HopAsync(m, "c.example", dns, x => x + "\r\n-- \r\nlist footer\r\n");
        m = await HopAsync(m, "d.example", dns);

        var result = await ValidateAsync(m, dns);
        Assert.True(result.IsPass, result.Reason);
        Assert.Equal(3, result.OldestPassingInstance);
    }

    [Fact]
    public async Task Oldest_pass_can_be_switched_off()
    {
        string m = await ChainAsync(3);
        var result = await ValidateAsync(m, null, new ArcValidatorOptions { ComputeOldestPass = false });
        Assert.True(result.IsPass);
        Assert.Null(result.OldestPassingInstance);
    }

    [Fact]
    public async Task Sealing_a_failed_chain_adds_a_cv_fail_set_and_it_never_validates_as_pass()
    {
        var dns = DnsForAllHops();
        string m = await ChainAsync(2, dns: dns);
        string tampered = ReplaceFirst(m, "Hello,", "Hullo,");

        var incoming = await ValidateAsync(tampered, dns);
        Assert.Equal(ArcChainStatus.Fail, incoming.Status);

        using var sealer = Sealer("c.example");
        var sealed3 = sealer.Seal(Bytes(tampered), ResultsFor("c.example", incoming), incoming);
        Assert.True(sealed3.IsSealed);
        Assert.Equal(3, sealed3.Instance);
        Assert.Equal(ArcChainStatus.Fail, sealed3.ChainValidationStatus);
        Assert.Contains("cv=fail", sealed3.Headers);

        var after = await ValidateAsync(sealed3.Headers + tampered, dns);
        Assert.Equal(ArcChainStatus.Fail, after.Status);
        Assert.Equal(ArcFailure.ChainFailedUpstream, after.Failure);
        Assert.Equal(3, after.FailedInstance);
    }

    [Fact]
    public async Task A_chain_whose_newest_seal_says_fail_is_not_extended()
    {
        var dns = DnsForAllHops();
        string m = await ChainAsync(1, dns: dns);
        string tampered = ReplaceFirst(m, "Hello,", "Hullo,");
        var incoming = await ValidateAsync(tampered, dns);
        using var sealer = Sealer("b.example");
        string failed = sealer.Seal(Bytes(tampered), ResultsFor("b.example", incoming), incoming).Headers + tampered;

        var again = await ValidateAsync(failed, dns);
        Assert.Equal(ArcChainStatus.Fail, again.Status);
        using var next = Sealer("c.example");
        var result = next.Seal(Bytes(failed), "mx.c.example; arc=fail", again);
        Assert.False(result.IsSealed);
        Assert.Contains("cv=fail", result.NotSealedReason);
        Assert.Empty(result.HeaderBytes.ToArray());
        Assert.Equal(0, result.Instance);
    }

    [Fact]
    public async Task Sealer_refuses_to_pass_a_chain_result_that_does_not_match_the_message()
    {
        string m = await ChainAsync(2);
        using var sealer = Sealer("c.example");
        var pass = new ArcChainResult(ArcChainStatus.Pass, "x") { InstanceCount = 1 };
        Assert.Throws<ArgumentException>(() => sealer.Seal(Bytes(m), "mx.c.example; none", pass));
        Assert.Throws<ArgumentException>(() => sealer.Seal(Bytes(m), "mx.c.example; none", new ArcChainResult(ArcChainStatus.None, "x")));
        Assert.Throws<ArgumentException>(() => sealer.Seal(Bytes(Original()), "mx.c.example; none", new ArcChainResult(ArcChainStatus.Pass, "x") { InstanceCount = 1 }));
    }

    [Fact]
    public void Sealer_rejects_bad_arguments()
    {
        using var sealer = Sealer("a.example");
        var none = new ArcChainResult(ArcChainStatus.None, "none");
        Assert.Throws<ArgumentException>(() => sealer.Seal(Bytes("Subject: x\r\n\r\nbody\r\n"), "mx.a.example; none", none));
        Assert.Throws<ArgumentException>(() => sealer.Seal(Bytes(Original()), "not valid ;;; (", none));
        Assert.Throws<ArgumentException>(() => sealer.Seal(Bytes(Original()), "mx.a.example; spf=pass reason=\"café\"", none));
        Assert.Throws<ArgumentNullException>(() => sealer.Seal(Bytes(Original()), (string)null!, none));
        Assert.Throws<ArgumentNullException>(() => sealer.Seal(Bytes(Original()), "mx.a.example; none", null!));
    }

    [Fact]
    public void Sealer_rejects_bad_options_and_keys()
    {
        var good = new ArcSealerOptions { Domain = "a.example", Selector = "s1" };
        Assert.Throws<ArgumentException>(() => new ArcSealer(new ArcSealerOptions { Domain = "not a domain", Selector = "s1" }, ArcKeys.For("a.example")));
        Assert.Throws<ArgumentException>(() => new ArcSealer(new ArcSealerOptions { Domain = "a.example", Selector = "bad selector" }, ArcKeys.For("a.example")));
        Assert.Throws<ArgumentException>(() => new ArcSealer(new ArcSealerOptions { Domain = "a.example", Selector = "s1", SignedHeaders = ["ARC-Seal"] }, ArcKeys.For("a.example")));
        Assert.Throws<ArgumentException>(() => new ArcSealer(new ArcSealerOptions { Domain = "a.example", Selector = "s1", SignedHeaders = ["Bad Name"] }, ArcKeys.For("a.example")));
        using var publicOnly = System.Security.Cryptography.RSA.Create();
        publicOnly.ImportSubjectPublicKeyInfo(ArcKeys.For("a.example").ExportSubjectPublicKeyInfo(), out _);
        Assert.Throws<ArgumentException>(() => new ArcSealer(good, publicOnly));
    }

    [Fact]
    public async Task Sealer_created_from_pem_owns_its_key_and_works()
    {
        var dns = DnsForAllHops();
        using var sealer = ArcSealer.FromPem(new ArcSealerOptions { Domain = "a.example", Selector = ArcKeys.Selector, Clock = new FixedTestClock(Now) }, ArcKeys.For("a.example").ExportPkcs8PrivateKeyPem());
        var result = sealer.Seal(Bytes(Original()), "mx.a.example; none", new ArcChainResult(ArcChainStatus.None, "none"));
        Assert.True((await ValidateAsync(result.Headers + Original(), dns)).IsPass);
        Assert.Equal("a.example", sealer.Domain);
        Assert.Equal(ArcKeys.Selector, sealer.Selector);
    }

    [Fact]
    public async Task Long_authentication_results_are_folded_and_still_validate()
    {
        var dns = DnsForAllHops();
        string ar = "mx.a.example; spf=pass smtp.mailfrom=alice@origin.example smtp.helo=client.example.org; dkim=pass header.d=origin.example header.s=selector1 header.b=Xb4F5k6S; dmarc=pass header.from=origin.example policy.p=reject reason=\"a quoted reason with several spaces inside it so folding must not split it\"";
        using var sealer = Sealer("a.example");
        var result = sealer.Seal(Bytes(Original()), ar, new ArcChainResult(ArcChainStatus.None, "none"));
        Assert.Contains("\r\n\t", result.Headers);
        Assert.Contains("\"a quoted reason with several spaces inside it so folding must not split it\"", result.Headers.Replace("\r\n\t", " "));
        Assert.True((await ValidateAsync(result.Headers + Original(), dns)).IsPass);
    }

    [Fact]
    public async Task Sealing_is_deterministic_for_a_fixed_clock()
    {
        using var sealer = Sealer("a.example");
        var none = new ArcChainResult(ArcChainStatus.None, "none");
        string one = sealer.Seal(Bytes(Original()), "mx.a.example; none", none).Headers;
        string two = sealer.Seal(Bytes(Original()), "mx.a.example; none", none).Headers;
        Assert.Equal(one, two);
        Assert.Contains("t=" + Now.ToUnixTimeSeconds(), one);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Messages_with_unusual_shapes_round_trip()
    {
        var dns = DnsForAllHops();
        string[] messages =
        [
            Original(string.Empty),
            Original("no final newline"),
            Original("trailing   spaces   \r\n\r\n\r\n"),
            Original("tabs\tin\tbody\r\n"),
            Original(new string('x', 5000) + "\r\n"),
            ReplaceFirst(Original(), "Subject: Test message", "Subject: folded\r\n subject with   spaces\r\n\tand tab"),
            ReplaceFirst(Original(), "Subject: Test message", "Subject: dup\r\nSubject: second subject"),
            "From: a@origin.example\r\n\r\n",
            "From: a@origin.example\r\nTo: b@c.example",
        ];

        foreach (string original in messages)
        {
            string m = original;
            for (int i = 0; i < 3; i++) { m = await HopAsync(m, Hops[i], dns); }
            var result = await ValidateAsync(m, dns);
            Assert.True(result.IsPass, result.Reason + "\n" + original);
        }
    }
}
