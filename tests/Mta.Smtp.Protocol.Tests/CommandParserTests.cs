using System.Text;
using Mta.Core;
using Mta.Smtp.Protocol;

namespace Mta.Smtp.Protocol.Tests;

public class CommandParserTests
{
    private static SmtpParseError Parse(string line, out SmtpCommand cmd) =>
        SmtpCommandParser.TryParse(Encoding.UTF8.GetBytes(line), SmtpParseOptions.Default, out cmd);

    [Theory]
    [InlineData("EHLO client.example.com", SmtpVerb.Ehlo, "client.example.com")]
    [InlineData("ehlo [192.0.2.1]", SmtpVerb.Ehlo, "[192.0.2.1]")]
    [InlineData("HELO my_host", SmtpVerb.Helo, "my_host")]
    public void Parses_greetings(string line, SmtpVerb verb, string arg)
    {
        Assert.Equal(SmtpParseError.None, Parse(line, out var c));
        Assert.Equal(verb, c.Verb);
        Assert.Equal(arg, c.Argument);
    }

    [Theory]
    [InlineData("EHLO")]
    [InlineData("HELO a b")]
    [InlineData("DATA extra")]
    [InlineData("QUIT now")]
    [InlineData("RSET x")]
    public void Rejects_bad_syntax(string line)
    {
        Assert.NotEqual(SmtpParseError.None, Parse(line, out _));
    }

    [Fact]
    public void Parses_mail_from_with_parameters()
    {
        Assert.Equal(SmtpParseError.None, Parse("MAIL FROM:<Sender@Example.COM> SIZE=1234 BODY=8BITMIME SMTPUTF8 AUTH=<>", out var c));
        Assert.Equal("Sender", c.Path.LocalPart);
        Assert.Equal("example.com", c.Path.Domain);
        Assert.Equal(1234, c.Mail.Size);
        Assert.Equal(SmtpBodyType.EightBitMime, c.Mail.BodyType);
        Assert.True(c.Mail.SmtpUtf8);
        Assert.Equal("<>", c.Mail.Auth);
    }

    [Fact]
    public void Parses_null_reverse_path()
    {
        Assert.Equal(SmtpParseError.None, Parse("MAIL FROM:<>", out var c));
        Assert.True(c.Path.IsNull);
    }

    [Fact]
    public void Strips_source_route()
    {
        Assert.Equal(SmtpParseError.None, Parse("RCPT TO:<@relay1.example,@relay2.example:user@dest.example>", out var c));
        Assert.Equal("user@dest.example", c.Path.ToString());
    }

    [Fact]
    public void Quoted_local_part_with_angle_bracket_is_handled()
    {
        Assert.Equal(SmtpParseError.None, Parse("RCPT TO:<\"a>b\"@example.com>", out var c));
        Assert.Equal("\"a>b\"", c.Path.LocalPart);
    }

    [Theory]
    [InlineData("MAIL FROM:user@example.com")]              // missing brackets
    [InlineData("MAIL FROM:<user@example.com")]             // unterminated
    [InlineData("MAIL FROM:<a@b.c> SIZE=abc")]
    [InlineData("MAIL FROM:<a@b.c> SIZE=1 SIZE=2")]
    [InlineData("MAIL FROM:<a@b.c> BODY=WHATEVER")]
    [InlineData("MAIL FROM:<a@b.c>junk")]
    [InlineData("MAIL FROM:<üser@b.c>")]                    // international without SMTPUTF8
    [InlineData("RCPT TO:<>")]
    [InlineData("RCPT TO:<a@b.c> NOTIFY")]
    public void Rejects_bad_mail_and_rcpt(string line)
    {
        Assert.NotEqual(SmtpParseError.None, Parse(line, out _));
    }

    [Fact]
    public void Unknown_parameters_are_reported_as_not_implemented()
    {
        Assert.Equal(SmtpParseError.ParameterNotImplemented, Parse("MAIL FROM:<a@b.c> FOO=1", out _));
    }

    [Fact]
    public void Parses_international_with_smtputf8()
    {
        Assert.Equal(SmtpParseError.None, Parse("MAIL FROM:<üser@bücher.example> SMTPUTF8", out var c));
        Assert.True(c.Path.IsInternational);
    }

    [Theory]
    [InlineData("BDAT 100", 100, false)]
    [InlineData("BDAT 0 LAST", 0, true)]
    [InlineData("bdat 5 last", 5, true)]
    public void Parses_bdat(string line, long size, bool last)
    {
        Assert.Equal(SmtpParseError.None, Parse(line, out var c));
        Assert.Equal(size, c.ChunkSize);
        Assert.Equal(last, c.LastChunk);
    }

    [Theory]
    [InlineData("BDAT")]
    [InlineData("BDAT -1")]
    [InlineData("BDAT 5 MORE")]
    [InlineData("BDAT 1234567890123")]
    public void Rejects_bad_bdat(string line) => Assert.NotEqual(SmtpParseError.None, Parse(line, out _));

    [Fact]
    public void Parses_auth_with_initial_response()
    {
        Assert.Equal(SmtpParseError.None, Parse("AUTH plain AGZvbwBiYXI=", out var c));
        Assert.Equal("PLAIN", c.Argument);
        Assert.Equal("AGZvbwBiYXI=", c.InitialResponse);
    }

    [Fact]
    public void Rejects_control_characters_and_long_lines()
    {
        Assert.Equal(SmtpParseError.InvalidCharacter, Parse("NOOP\0", out _));
        Assert.Equal(SmtpParseError.InvalidCharacter, Parse("NOOP\u0001", out _));
        Assert.Equal(SmtpParseError.LineTooLong, Parse("NOOP " + new string('a', 3000), out _));
    }

    [Fact]
    public void Unknown_verb()
    {
        Assert.Equal(SmtpParseError.UnknownCommand, Parse("FROB it", out _));
    }

    [Fact]
    public void Random_input_never_throws()
    {
        var rng = new Random(12345);
        byte[] buf = new byte[200];
        string[] seeds = ["MAIL FROM:<a@b.c> ", "RCPT TO:<", "EHLO ", "BDAT ", "AUTH "];
        for (int i = 0; i < 20000; i++)
        {
            int n = rng.Next(0, buf.Length);
            rng.NextBytes(buf.AsSpan(0, n));
            if (i % 2 == 0)
            {
                var seed = Encoding.ASCII.GetBytes(seeds[i % seeds.Length]);
                seed.CopyTo(buf, 0);
                n = Math.Max(n, seed.Length);
            }

            SmtpCommandParser.TryParse(buf.AsSpan(0, n), SmtpParseOptions.Default, out _);
        }
    }
}
