using System.Text;
using Mta.Host.Tests.Api;
using Mta.Host.Tests.Inbound;
using Mta.Storage;

namespace Mta.Host.Tests.InboundE2E;

/// <summary>
/// Text a stranger controls (the greeting name, the sender and recipient addresses, the subject, header values) reaches the stores of both backends and the API. PostgreSQL refuses NUL and lone
/// surrogates in text where SQLite does not; the receive path must neither fail on them nor store them (decision 101, INJ-2). Whatever the sender sends, it is either refused in the dialog or stored
/// cleaned, with a reply that is not a server error.
/// </summary>
public abstract class InboundHostileTextTests(LabBackend backend)
{
    private static string Raw(params byte[] bytes) => Encoding.Latin1.GetString(bytes);

    public static IEnumerable<object[]> Subjects()
    {
        yield return ["a NUL in an encoded word", "=?utf-8?q?a=00b?="];
        yield return ["lone high surrogate in an encoded word", "=?utf-8?b?7aCA?="];
        yield return ["utf-16 lone surrogate", "=?utf-16be?b?2AA=?="];
        yield return ["invalid utf-8 bytes", Raw(0xC3, 0x28, 0xA0, 0xA1, 0xE2, 0x28, 0xA1, 0xF0, 0x28, 0x8C, 0xBC)];
        yield return ["overlong and truncated sequences", Raw(0xC0, 0xAF, 0xE0, 0x80, 0xAF, 0xF4, 0x90, 0x80, 0x80, 0xE2, 0x82)];
        yield return ["bidi overrides and zero width characters", "\u202Eevil\u202C \u200B\u200D\u2066x\u2069"];
        yield return ["a very long subject", new string('s', 5_000)];
        yield return ["control characters", "tab\there\u0001\u0002\u007f\u0085\u2028\u2029"];
        yield return ["emoji outside the BMP, cut in the middle", new string('x', 255) + "\ud83d\ude00\ud83d\ude00"];
        yield return ["an unknown charset", "=?x-unknown?q?hello?="];
        yield return ["many encoded words", string.Concat(Enumerable.Repeat("=?utf-8?q?ab?= ", 600))];
        yield return ["backslashes and quotes", "\\\"'; DROP TABLE inbound_message; --"];
    }

    [Theory]
    [MemberData(nameof(Subjects))]
    public async Task A_subject_a_stranger_controls_is_stored_cleaned_or_refused_never_a_server_error_and_never_in_a_form_the_database_would_refuse(string name, string subject)
    {
        _ = name;
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true });
        if (lab is null)
        {
            return;
        }

        string message = $"From: bob@sender.test\r\nTo: support@example.org\r\nSubject: {subject}\r\nDate: Fri, 16 Oct 2026 12:00:00 +0000\r\nMessage-ID: <h1@sender.test>\r\n\r\nbody\r\n";
        await using FakeMta mta = await lab.ConnectedAsync();
        FakeMta.Reply reply = await mta.SendAsync("bob@sender.test", "support@example.org", message);

        Assert.True(reply.Code is 250 or 554 or 552, reply.ToString());   // stored, or refused as malformed: never a 4xx for the server's own failure
        if (reply.Code != 250)
        {
            return;
        }

        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        if (stored.Subject is { } text)
        {
            Assert.True(text.Length <= 256);
            Assert.DoesNotContain(text, c => char.IsControl(c));
            Assert.DoesNotContain(text, c => c is >= '‪' and <= '‮' or >= '⁦' and <= '⁩');
            for (int i = 0; i < text.Length; i++)
            {
                Assert.False(char.IsLowSurrogate(text[i]) && (i == 0 || !char.IsHighSurrogate(text[i - 1])), "a lone low surrogate was stored");
                Assert.False(char.IsHighSurrogate(text[i]) && (i == text.Length - 1 || !char.IsLowSurrogate(text[i + 1])), "a lone high surrogate was stored");
            }
        }

        // The API reads it back: a search by a piece of it, the detail, as JSON.
        ApiClient alice = await lab.Api!.SignedInAsync("alice");
        Reply detail = await alice.GetAsync("/api/v1/inbound/messages/" + Mta.Host.Api.ApiJson.Id(stored.Id));
        Assert.Equal(System.Net.HttpStatusCode.OK, detail.Status);
        string piece = (stored.Subject ?? "x")[..Math.Min(50, (stored.Subject ?? "x").Length)];
        if (piece.Length > 0 && char.IsHighSurrogate(piece[^1]))
        {
            piece = piece[..^1];
        }

        Assert.Equal(System.Net.HttpStatusCode.OK, (await alice.GetAsync("/api/v1/inbound/messages?subject=" + Uri.EscapeDataString(piece))).Status);
        lab.AssertNoErrorsLogged();
    }

    public static IEnumerable<object[]> Dialogs()
    {
        yield return ["a very long greeting name", "EHLO " + new string('a', 600) + ".test", "bob@sender.test", "support@example.org"];
        yield return ["a greeting name with a NUL", "EHLO bad\0name.test", "bob@sender.test", "support@example.org"];
        yield return ["a greeting name with 8-bit bytes", "EHLO " + Raw(0xC3, 0xA9, 0xFF, 0xFE) + ".test", "bob@sender.test", "support@example.org"];
        yield return ["an international sender", "EHLO mail.sender.test", "j\u00f6rg@b\u00fccher.example", "support@example.org"];
        yield return ["an international recipient", "EHLO mail.sender.test", "bob@sender.test", "SUPPORT@EXAMPLE.ORG"];
        yield return ["invalid utf-8 in the sender", "EHLO mail.sender.test", Raw(0xC3, 0x28) + "@sender.test", "support@example.org"];
        yield return ["a long sender", "EHLO mail.sender.test", new string('l', 64) + "@" + new string('d', 60) + ".test", "support@example.org"];
        yield return ["a sender in upper case", "EHLO mail.sender.test", "BOB@SENDER.TEST", "support@example.org"];
        yield return ["an uppercase turkish i", "EHLO mail.sender.test", "\u0130stanbul@sender.test", "support@example.org"];
    }

    [Theory]
    [MemberData(nameof(Dialogs))]
    public async Task Names_and_addresses_from_the_dialog_are_stored_cleaned_or_refused_and_never_make_the_store_fail(string name, string ehlo, string from, string recipient)
    {
        _ = name;
        await using InboundLab? lab = await InboundLab.StartAsync(backend, new LabOptions { WithApi = true });
        if (lab is null)
        {
            return;
        }

        await using FakeMta mta = await lab.ConnectAsync();
        FakeMta.Reply hello = await mta.CommandAsync(ehlo);
        if (hello.Code != 250)
        {
            Assert.InRange(hello.Code, 500, 599);   // a greeting name nobody can use is refused in the dialog
            return;
        }

        FakeMta.Reply mailReply = await mta.CommandAsync($"MAIL FROM:<{from}> SMTPUTF8");
        if (mailReply.Code != 250)
        {
            Assert.InRange(mailReply.Code, 500, 599);
            return;
        }

        FakeMta.Reply rcpt = await mta.CommandAsync($"RCPT TO:<{recipient}>");
        if (rcpt.Code != 250)
        {
            Assert.InRange(rcpt.Code, 500, 599);
            return;
        }

        FakeMta.Reply done = await mta.DataAsync(InboundLab.Message());
        Assert.Equal(250, done.Code);

        InboundMessage stored = Assert.Single(await lab.MessagesAsync(InboundLab.Acme));
        Assert.True((stored.Helo ?? "").Length <= 255);
        Assert.DoesNotContain(stored.Helo ?? "", c => char.IsControl(c));
        Assert.Equal(stored.EnvelopeFrom, stored.EnvelopeFrom.ToLowerInvariant());
        Assert.Equal(stored.EnvelopeTo, stored.EnvelopeTo.ToLowerInvariant());
        ApiClient alice = await lab.Api!.SignedInAsync("alice");
        Reply listed = await alice.GetAsync("/api/v1/inbound/messages?sender=" + Uri.EscapeDataString(stored.EnvelopeFrom) + "&recipient=" + Uri.EscapeDataString(stored.EnvelopeTo));
        Assert.Equal(1, listed["items"].GetArrayLength());   // what is stored is what a search finds
        lab.AssertNoErrorsLogged();
    }
}

public sealed class SqliteInboundHostileTextTests() : InboundHostileTextTests(LabBackend.Sqlite);

public sealed class PostgresInboundHostileTextTests() : InboundHostileTextTests(LabBackend.Postgres);
