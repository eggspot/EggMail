using Mta.RemoteMta.Tests.Harness;
using Mta.Storage;

namespace Mta.RemoteMta.Tests.Scenarios;

/// <summary>The lab itself: if these fail the harness is broken, not the engine.</summary>
public class HarnessSmokeTests
{
    [Fact]
    public async Task A_message_is_delivered_to_a_postfix_like_peer_and_the_peer_saw_the_whole_conversation()
    {
        await using var lab = new MtaLab();
        var mx = lab.AddMta("mx.dest.example", Personalities.Postfix());
        lab.Mx("dest.example", 10, "mx.dest.example");

        var id = await lab.SendAsync(["rcpt@dest.example"]);
        var events = await lab.WaitForEventAsync(id, MessageEventType.Delivered);

        var message = Assert.Single(mx.Messages);
        Assert.Equal("sender@example.org", message.Sender);
        Assert.Equal(["rcpt@dest.example"], message.Recipients);
        Assert.Contains("Subject: Hello", message.Text);
        var delivered = events.Single(e => e.Type == MessageEventType.Delivered);
        Assert.Equal(250, delivered.SmtpCode);
        Assert.Equal("2.0.0", delivered.EnhancedCode);
        Assert.Equal("mx.dest.example", delivered.MxHost);
        Assert.Equal(["EHLO", "MAIL", "RCPT", "DATA"], mx.Sessions.Single().Verbs.Take(4));
    }

    [Fact]
    public async Task The_clock_of_the_lab_only_moves_when_the_test_moves_it()
    {
        await using var lab = new MtaLab();
        var before = lab.Clock.UtcNow;
        await Task.Delay(50);
        Assert.Equal(before, lab.Clock.UtcNow);
        lab.Advance(TimeSpan.FromHours(3));
        Assert.Equal(before.AddHours(3), lab.Clock.UtcNow);
    }
}
