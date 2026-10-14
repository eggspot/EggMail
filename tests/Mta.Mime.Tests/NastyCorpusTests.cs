using System.Diagnostics;
using Xunit.Abstractions;

namespace Mta.Mime.Tests;

public class NastyCorpusTests(ITestOutputHelper output)
{
    public static IEnumerable<object[]> Cases() => NastyCorpus.All().Select(c => new object[] { c.Name });

    private static readonly Lazy<Dictionary<string, byte[]>> Lookup = new(() => NastyCorpus.All().ToDictionary(c => c.Name, c => c.Data));

    [Fact]
    public void Corpus_has_at_least_sixty_distinct_messages()
    {
        var all = NastyCorpus.All().ToList();
        Assert.True(all.Count >= 60, $"only {all.Count}");
        Assert.Equal(all.Count, all.Select(c => c.Name).Distinct().Count());
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Every_parser_survives_with_bounded_time_and_memory(string name)
    {
        byte[] data = Lookup.Value[name];
        long allocated = HangGuard.Run(() =>
        {
            long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
            Pipeline.RunEverything(data);
            return GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;
        }, name);
        output.WriteLine($"{name}: {data.Length / 1024} KiB in, {allocated / 1024} KiB allocated");

        // Allocation is the deterministic bound ("not unbounded"); a hang is caught by the guard. Elapsed time is not asserted: it measures the load of the host.
        Assert.True(allocated < (64L * data.Length) + (48L << 20), $"{name} allocated {allocated / 1024} KiB for {data.Length / 1024} KiB input");
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Strict_limits_are_honoured(string name)
    {
        var limits = new MimeLimits { MaxHeaderBytes = 2048, MaxHeaderCount = 20, MaxDepth = 3, MaxParts = 10, MaxDecodedBytes = 4096, MaxParameters = 4, MaxAddresses = 5, MaxHeaderValueBytes = 512 };
        Pipeline.RunEverything(Lookup.Value[name], limits);
    }

    // ---- specific expectations for the classic attacks

    [Fact]
    public void Bare_cr_injection_does_not_create_a_bcc_header()
    {
        var h = HeaderList.Parse(Lookup.Value["18-bare-cr-header-injection"]);
        Assert.Equal(-1, h.IndexOf("Bcc"));
        Assert.True(h.Anomalies.HasAny(MimeAnomaly.BareCr));
        Assert.True(MessageValidator.Validate(Lookup.Value["18-bare-cr-header-injection"]).HasErrors);
    }

    [Fact]
    public void Encoded_word_crlf_does_not_leak_into_extracted_fields()
    {
        var c = MessageContentExtractor.Extract(Lookup.Value["27-encoded-word-crlf-injection"]);
        Assert.DoesNotContain('\r', c.Subject!);
        Assert.DoesNotContain('\n', c.Subject!);
        // The faithful decoder keeps the control characters, so re-emitting them unchecked is rejected by the builder.
        var h = HeaderList.Parse(Lookup.Value["27-encoded-word-crlf-injection"]);
        string decoded = h[0].DecodedValue;
        Assert.Contains('\n', decoded);
        var b = new MessageBuilder(new MessageBuilderOptions { MessageIdDomain = "example.com" }) { From = Mailbox.Create(null, "a@example.com"), Subject = decoded };
        Assert.Throws<HeaderInjectionException>(() => b.Build());
    }

    [Fact]
    public void Header_count_bombs_are_cut_at_the_limit()
    {
        var h = HeaderList.Parse(Lookup.Value["05-ten-thousand-header-lines"]);
        Assert.Equal(1000, h.Count);
        Assert.True(h.Anomalies.HasAny(MimeAnomaly.TooManyHeaders));
        Assert.Equal("body", System.Text.Encoding.ASCII.GetString(h.Body.Span));
    }

    [Fact]
    public void Nesting_bombs_are_cut_at_the_depth_limit()
    {
        var m = MimeMessage.Parse(Lookup.Value["49-nesting-bomb-multipart-5000"]);
        Assert.True(m.Anomalies.HasAny(MimeAnomaly.MaxDepthExceeded));
        Assert.True(m.EnumerateParts().Max(p => p.Depth) <= MimeLimits.Default.MaxDepth);
        var r = MimeMessage.Parse(Lookup.Value["50-nesting-bomb-rfc822-3000"]);
        Assert.True(r.Anomalies.HasAny(MimeAnomaly.MaxDepthExceeded));
        Assert.True(r.PartCount <= MimeLimits.Default.MaxDepth + 2);
    }

    [Fact]
    public void Part_bombs_are_cut_at_the_part_limit()
    {
        var m = MimeMessage.Parse(Lookup.Value["51-ten-thousand-parts"]);
        Assert.Equal(1000, m.PartCount);
        Assert.True(m.Anomalies.HasAny(MimeAnomaly.TooManyParts));
    }

    [Fact]
    public void Utf7_and_unknown_charsets_do_not_decode_as_utf7()
    {
        var c = MessageContentExtractor.Extract(Lookup.Value["77-base64-dump-in-text-plain-utf7"]);
        Assert.Equal("+2D3cAA-", c.TextBody); // the base64 payload is "+2D3cAA-"; UTF-7 would turn it into an emoji
        Assert.True(c.Anomalies.HasAny(MimeAnomaly.UnknownCharset));
    }

    [Fact]
    public void Truncated_base64_yields_what_is_complete()
    {
        var c = MessageContentExtractor.Extract(Lookup.Value["69-truncated-base64"]);
        Assert.Equal(7, Assert.Single(c.Attachments).Size); // "ABCDEFG"
    }

    [Fact]
    public void Two_megabyte_base64_attachment_is_indexed_not_stored()
    {
        var c = MessageContentExtractor.Extract(Lookup.Value["72-base64-two-megabytes"]);
        var a = Assert.Single(c.Attachments);
        Assert.Equal("big.bin", a.FileName);
        Assert.Equal(27_000L * 57, a.Size);
        Assert.Null(c.TextBody);
    }

    [Fact]
    public void Path_traversal_file_names_are_sanitized_of_control_characters_only()
    {
        var c = MessageContentExtractor.Extract(Lookup.Value["85-filename-path-traversal-and-controls"]);
        Assert.Equal(2, c.Attachments.Count);
        Assert.All(c.Attachments, a => Assert.DoesNotContain(a.FileName!, char.IsControl));
        // Storage code must treat the name as data; the builder strips directories when re-attaching:
        var attachment = new BuilderAttachment(c.Attachments[0].FileName!, "application/zip", default);
        Assert.DoesNotContain('/', attachment.FileName);
        Assert.DoesNotContain('\\', attachment.FileName);
    }

    [Fact]
    public void Duplicate_singletons_are_all_reported()
    {
        var r = MessageValidator.Validate(Lookup.Value["20-duplicate-singletons"]);
        Assert.True(r.Has(MessageIssueCode.DuplicateSingletonHeader));
        Assert.Contains(r.Issues, i => i.HeaderName == "Subject");
        Assert.Contains(r.Issues, i => i.HeaderName == "From");
    }

    [Fact]
    public void Mail_loop_corpus_message_is_flagged()
    {
        Assert.True(MessageValidator.Validate(Lookup.Value["21-five-thousand-received"]).Has(MessageIssueCode.TooManyReceivedHeaders));
    }
}
