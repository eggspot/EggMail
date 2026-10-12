using System.Text;
using Mta.Auth.Arc;
using Mta.Dkim;
using Mta.Dns;
using static Mta.Auth.Tests.Arc.ArcMsg;

namespace Mta.Auth.Tests.Arc;

public class ArcTamperTests
{
    private static async Task AssertFailsAsync(string message, ArcFailure expected, int? instance = null, StaticDnsResolver? dns = null, ArcValidatorOptions? options = null)
    {
        var r = await ValidateAsync(message, dns, options);
        Assert.Equal(ArcChainStatus.Fail, r.Status);
        Assert.Equal(expected, r.Failure);
        if (instance is not null) { Assert.Equal(instance, r.FailedInstance); }
    }

    [Fact]
    public async Task Body_modification_fails_the_message_signature()
    {
        string m = await ChainAsync(3);
        await AssertFailsAsync(ReplaceFirst(m, "This is the body.", "This is the BODY."), ArcFailure.BodyHashMismatch, 3);
    }

    [Fact]
    public async Task Signed_header_modification_fails_the_message_signature()
    {
        string m = await ChainAsync(3);
        await AssertFailsAsync(ReplaceFirst(m, "Subject: Test message", "Subject: Other"), ArcFailure.MessageSignatureMismatch, 3);
    }

    [Fact]
    public async Task Unsigned_header_changes_do_not_matter()
    {
        string m = await ChainAsync(2);
        var r = await ValidateAsync(ReplaceFirst(m, "Received: from client", "Received: from someone-else"));
        Assert.True(r.IsPass, r.Reason);
    }

    [Fact]
    public async Task Modifying_an_earlier_results_header_fails_the_newer_seals()
    {
        string m = await ChainAsync(3);
        string tampered = ReplaceFirst(m, "ARC-Authentication-Results: i=1; mx.a.example; spf=pass", "ARC-Authentication-Results: i=1; mx.a.example; spf=fail");
        await AssertFailsAsync(tampered, ArcFailure.SealMismatch, 3);
    }

    [Fact]
    public async Task Modifying_the_newest_results_header_fails_its_seal()
    {
        string m = await ChainAsync(2);
        await AssertFailsAsync(ReplaceFirst(m, "ARC-Authentication-Results: i=2; mx.b.example; spf=pass", "ARC-Authentication-Results: i=2; mx.b.example; spf=none"), ArcFailure.SealMismatch, 2);
    }

    [Fact]
    public async Task Modifying_an_earlier_message_signature_fails_the_seals()
    {
        string m = await ChainAsync(3);
        var (fields, body) = Split(m);
        int i = fields.FindIndex(f => f.StartsWith("ARC-Message-Signature: i=1;", StringComparison.Ordinal));
        fields[i] = fields[i].Replace("a=rsa-sha256;", "a=rsa-sha256; x=1;", StringComparison.Ordinal);
        await AssertFailsAsync(Join(fields, body), ArcFailure.SealMismatch, 3);
    }

    [Fact]
    public async Task Removing_the_newest_set_leaves_a_valid_shorter_chain_only_if_the_message_is_unchanged()
    {
        string m = await ChainAsync(3);
        var (fields, body) = Split(m);
        fields.RemoveAll(f => IsArc(f) && InstanceOf(f) == 3);
        var r = await ValidateAsync(Join(fields, body));
        Assert.True(r.IsPass, r.Reason);
        Assert.Equal(2, r.InstanceCount);
    }

    [Fact]
    public async Task Removing_a_middle_set_is_an_instance_gap()
    {
        string m = await ChainAsync(3);
        var (fields, body) = Split(m);
        fields.RemoveAll(f => IsArc(f) && InstanceOf(f) == 2);
        await AssertFailsAsync(Join(fields, body), ArcFailure.InstanceGap, 2);
    }

    [Fact]
    public async Task Removing_the_first_set_is_an_instance_gap()
    {
        string m = await ChainAsync(2);
        var (fields, body) = Split(m);
        fields.RemoveAll(f => IsArc(f) && InstanceOf(f) == 1);
        await AssertFailsAsync(Join(fields, body), ArcFailure.InstanceGap, 1);
    }

    [Theory]
    [InlineData("ARC-Seal:")]
    [InlineData("ARC-Message-Signature:")]
    [InlineData("ARC-Authentication-Results:")]
    public async Task A_set_missing_one_header_is_incomplete(string name)
    {
        string m = await ChainAsync(2);
        var (fields, body) = Split(m);
        fields.RemoveAll(f => f.StartsWith(name + " i=2;", StringComparison.Ordinal));
        await AssertFailsAsync(Join(fields, body), ArcFailure.IncompleteSet, 2);
    }

    [Theory]
    [InlineData("ARC-Seal:")]
    [InlineData("ARC-Message-Signature:")]
    [InlineData("ARC-Authentication-Results:")]
    public async Task Duplicate_headers_for_an_instance_fail(string name)
    {
        string m = await ChainAsync(2);
        var (fields, body) = Split(m);
        string dup = fields.First(f => f.StartsWith(name + " i=2;", StringComparison.Ordinal));
        fields.Insert(0, dup);
        await AssertFailsAsync(Join(fields, body), ArcFailure.DuplicateInstance, 2);
    }

    [Fact]
    public async Task Reordering_header_positions_does_not_matter_but_swapping_instances_does()
    {
        string m = await ChainAsync(2);
        var (fields, body) = Split(m);
        var arc = fields.Where(IsArc).ToList();
        var rest = fields.Where(f => !IsArc(f)).ToList();
        arc.Reverse();
        Assert.True((await ValidateAsync(string.Concat(arc) + string.Concat(rest) + body)).IsPass);

        // Swap the instance numbers inside the set headers: the seals no longer cover what they say.
        string swapped = m.Replace("i=1;", "i=X;", StringComparison.Ordinal).Replace("i=2;", "i=1;", StringComparison.Ordinal).Replace("i=X;", "i=2;", StringComparison.Ordinal);
        var r = await ValidateAsync(swapped);
        Assert.Equal(ArcChainStatus.Fail, r.Status);
    }

    [Fact]
    public async Task Changing_cv_values_fails()
    {
        string m = await ChainAsync(2);
        // cv=pass -> cv=none in instance 2 is structurally invalid.
        await AssertFailsAsync(ReplaceFirst(m, "cv=pass", "cv=none"), ArcFailure.InvalidChainValidationStatus, 2);
        // cv=none -> cv=pass in instance 1 is structurally invalid.
        await AssertFailsAsync(ReplaceFirst(m, "cv=none", "cv=pass"), ArcFailure.InvalidChainValidationStatus, 1);
        // cv=pass -> cv=fail is an upstream failure.
        await AssertFailsAsync(ReplaceFirst(m, "cv=pass", "cv=fail"), ArcFailure.ChainFailedUpstream, 2);
        // cv=bogus is a parse error.
        await AssertFailsAsync(ReplaceFirst(m, "cv=pass", "cv=maybe"), ArcFailure.MalformedHeader);
    }

    [Fact]
    public async Task A_seal_signed_with_the_wrong_key_fails()
    {
        // b.example signs with a key that is not the one published for it.
        var dns = DnsForAllHops();
        string first = await HopAsync(Original(), "a.example", dns);
        var incoming = await ValidateAsync(first, dns);
        using var wrong = new ArcSealer(new ArcSealerOptions { Domain = "b.example", Selector = ArcKeys.Selector, Clock = new FixedTestClock(Now) }, ArcKeys.Stranger);
        string m = wrong.Seal(Bytes(first), ResultsFor("b.example", incoming), incoming).Headers + first;
        await AssertFailsAsync(m, ArcFailure.MessageSignatureMismatch, 2, dns);
    }

    [Fact]
    public async Task A_revoked_key_fails()
    {
        string m = await ChainAsync(2);
        var dns = DnsForAllHops();
        dns = new StaticDnsResolver().AddTxt(ArcKeys.Selector + "._domainkey.a.example", "v=DKIM1; k=rsa; p=")
            .AddTxt(ArcKeys.Selector + "._domainkey.b.example", DkimKeyTools.FormatDnsTxtValue(ArcKeys.For("b.example")));
        await AssertFailsAsync(m, ArcFailure.KeyRevoked, 1, dns);
    }

    [Fact]
    public async Task Missing_key_and_malformed_key_records_fail_permanently()
    {
        string m = await ChainAsync(1);
        var r = await ValidateAsync(m, new StaticDnsResolver());
        Assert.Equal(ArcFailure.KeyNotFound, r.Failure);
        Assert.False(r.IsTransient);

        var malformed = new StaticDnsResolver().AddTxt(ArcKeys.Selector + "._domainkey.a.example", "v=DKIM1; k=rsa; p=@@@@");
        Assert.Equal(ArcFailure.MalformedKeyRecord, (await ValidateAsync(m, malformed)).Failure);

        var ed = new StaticDnsResolver().AddTxt(ArcKeys.Selector + "._domainkey.a.example", "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=");
        Assert.Equal(ArcFailure.KeyTypeMismatch, (await ValidateAsync(m, ed)).Failure);
    }

    [Fact]
    public async Task Dns_failure_is_a_transient_failure()
    {
        string m = await ChainAsync(1);
        var dns = new StaticDnsResolver().Fail(ArcKeys.Selector + "._domainkey.a.example", DnsRecordType.TXT, DnsRcode.ServerFailure);
        var r = await ValidateAsync(m, dns);
        Assert.Equal(ArcChainStatus.Fail, r.Status);
        Assert.Equal(ArcFailure.KeyDnsError, r.Failure);
        Assert.True(r.IsTransient);
    }

    [Fact]
    public async Task Small_keys_are_rejected_below_the_configured_minimum()
    {
        string m = await ChainAsync(1);
        var r = await ValidateAsync(m, null, new ArcValidatorOptions { MinimumKeyBits = 4096 });
        Assert.Equal(ArcFailure.KeyTooSmall, r.Failure);
        r = await ValidateAsync(m, null, new ArcValidatorOptions { MaximumKeyBits = 1024 });
        Assert.Equal(ArcFailure.KeyTooLarge, r.Failure);
    }

    [Fact]
    public async Task Unsupported_algorithms_fail()
    {
        string m = await ChainAsync(1);
        await AssertFailsAsync(m.Replace("a=rsa-sha256", "a=ed25519-sha256", StringComparison.Ordinal), ArcFailure.UnsupportedAlgorithm, 1);
        await AssertFailsAsync(m.Replace("a=rsa-sha256", "a=rsa-sha1", StringComparison.Ordinal), ArcFailure.UnsupportedAlgorithm, 1);
    }

    [Fact]
    public async Task Fifty_one_instances_fail_and_fifty_are_accepted_structurally()
    {
        string m = await ChainAsync(1);
        var (fields, body) = Split(m);
        var extra = new StringBuilder();
        for (int i = 51; i >= 2; i--)
        {
            extra.Append($"ARC-Seal: i={i}; a=rsa-sha256; cv=pass; d=a.example; s=arc1; b=AAAA\r\n");
            extra.Append($"ARC-Message-Signature: i={i}; a=rsa-sha256; d=a.example; s=arc1; h=from; bh=AAAA; b=AAAA\r\n");
            extra.Append($"ARC-Authentication-Results: i={i}; mx.a.example; none\r\n");
        }

        await AssertFailsAsync(extra.ToString() + m, ArcFailure.TooManyInstances);

        // 50 sets pass the structure checks and then fail cryptographically, not structurally.
        var fifty = new StringBuilder();
        for (int i = 50; i >= 2; i--)
        {
            fifty.Append($"ARC-Seal: i={i}; a=rsa-sha256; cv=pass; d=a.example; s=arc1; b=AAAA\r\n");
            fifty.Append($"ARC-Message-Signature: i={i}; a=rsa-sha256; d=a.example; s=arc1; h=from; bh=AAAA; b=AAAA\r\n");
            fifty.Append($"ARC-Authentication-Results: i={i}; mx.a.example; none\r\n");
        }

        var r = await ValidateAsync(fifty.ToString() + m);
        Assert.Equal(ArcFailure.BodyHashMismatch, r.Failure);
        Assert.Equal(50, r.InstanceCount);

        await AssertFailsAsync(fifty.ToString() + m, ArcFailure.TooManyInstances, options: new ArcValidatorOptions { MaxInstances = 10 });
    }

    [Fact]
    public async Task Distinct_key_lookups_are_bounded()
    {
        string m = await ChainAsync(4);
        var counting = DnsForAllHops();
        await AssertFailsAsync(m, ArcFailure.TooManyKeyLookups, null, counting, new ArcValidatorOptions { MaxKeyLookups = 2 });
    }

    [Fact]
    public async Task Oversized_headers_and_too_many_headers_fail_cleanly()
    {
        string m = await ChainAsync(1);
        await AssertFailsAsync(m, ArcFailure.HeaderTooLong, null, null, new ArcValidatorOptions { MaxHeaderLength = 100 });
        await AssertFailsAsync(m, ArcFailure.TooManyHeaders, null, null, new ArcValidatorOptions { MaxHeaderCount = 5 });
    }

    [Fact]
    public async Task Malformed_headers_fail_without_throwing()
    {
        string m = await ChainAsync(1);
        string[] mutations =
        [
            "ARC-Seal: i=0; a=rsa-sha256; cv=none; d=a.example; s=arc1; b=AAAA\r\n",
            "ARC-Seal: i=01; a=rsa-sha256; cv=none; d=a.example; s=arc1; b=AAAA\r\n",
            "ARC-Seal: i=-1; a=rsa-sha256; cv=none; d=a.example; s=arc1; b=AAAA\r\n",
            "ARC-Seal: a=rsa-sha256; cv=none; d=a.example; s=arc1; b=AAAA\r\n",
            "ARC-Seal: i=1; i=1; a=rsa-sha256; cv=none; d=a.example; s=arc1; b=AAAA\r\n",
            "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=a.example; s=arc1; h=from; b=AAAA\r\n",
            "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=bad..domain; s=arc1; b=AAAA\r\n",
            "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=a.example; s=arc1; b=!!!\r\n",
            "ARC-Message-Signature: i=1; a=rsa-sha256; d=a.example; s=arc1; h=from; bh=AAAA; l=5; b=AAAA\r\n",
            "ARC-Message-Signature: i=1; a=rsa-sha256; d=a.example; s=arc1; h=arc-seal; bh=AAAA; b=AAAA\r\n",
            "ARC-Message-Signature: i=1; a=rsa-sha256; d=a.example; s=arc1; bh=AAAA; b=AAAA\r\n",
            "ARC-Authentication-Results: mx.example; none\r\n",
            "ARC-Authentication-Results: i=1 mx.example\r\n",
            "ARC-Authentication-Results: i=1;\r\n",
            "ARC-Seal:\r\n",
        ];

        foreach (string bad in mutations)
        {
            var r = await ValidateAsync(bad + m);
            Assert.Equal(ArcChainStatus.Fail, r.Status);
            Assert.Equal(ArcFailure.MalformedHeader, r.Failure);
        }
    }

    [Fact]
    public async Task Folding_and_whitespace_variants_of_a_valid_chain_still_validate()
    {
        string m = await ChainAsync(1);
        // Extra folding whitespace inside the b= value is not part of the signed text and is ignored when decoding the signature.
        var (fields, body) = Split(m);
        int i = fields.FindIndex(f => f.StartsWith("ARC-Seal:", StringComparison.Ordinal));
        string field = fields[i];
        int b = field.LastIndexOf("b=", StringComparison.Ordinal) + 2;
        string value = field.Substring(b).TrimEnd('\r', '\n').Replace("\r\n\t", string.Empty, StringComparison.Ordinal);
        fields[i] = field.Substring(0, b) + value.Insert(10, "\r\n\t ").Insert(20, "  ") + "\r\n";
        var r = await ValidateAsync(Join(fields, body));
        Assert.Equal(ArcChainStatus.Pass, r.Status);
    }

    [Fact]
    public async Task Cancellation_is_propagated()
    {
        string m = await ChainAsync(1);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        var dns = new CancellingResolver();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await new ArcValidator(dns).ValidateAsync(Bytes(m), cts.Token));
    }

    private sealed class CancellingResolver : IDnsResolver
    {
        public ValueTask<DnsResponse> QueryAsync(string name, DnsRecordType type, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new DnsResponse());
        }
    }
}
