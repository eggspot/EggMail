using System.Text;

namespace Mta.Mime.Tests;

public class HeaderFolderTests
{
    [Fact]
    public void Short_values_are_not_folded() => Assert.Equal("Subject: Hello world\r\n", HeaderFolder.Fold("Subject", "Hello world"));

    [Fact]
    public void Empty_value_has_no_trailing_space() => Assert.Equal("X-Empty:\r\n", HeaderFolder.Fold("X-Empty", "   "));

    [Fact]
    public void Long_values_fold_at_whitespace_within_78_columns()
    {
        string value = string.Join(' ', Enumerable.Range(0, 60).Select(i => "word" + i));
        string folded = HeaderFolder.Fold("X-Long", value);
        string[] lines = folded.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);

        Assert.True(lines.Length > 3);
        Assert.All(lines, l => Assert.True(l.Length <= 78, l));
        Assert.All(lines.Skip(1), l => Assert.StartsWith(" ", l));
        Assert.Equal("X-Long: " + value, folded.Replace("\r\n", string.Empty, StringComparison.Ordinal).TrimEnd());
    }

    [Fact]
    public void Folding_is_reversed_by_unfolding_exactly()
    {
        string value = "a  b\tc " + string.Join(' ', Enumerable.Repeat("token", 40)) + "  end";
        string folded = HeaderFolder.Fold("X-Test", value);
        var header = HeaderList.Parse(Encoding.ASCII.GetBytes(folded + "\r\n"))[0];
        Assert.Equal(value, header.Value);
    }

    [Fact]
    public void A_token_longer_than_78_is_kept_whole_on_its_own_line()
    {
        string token = new string('x', 200);
        string folded = HeaderFolder.Fold("X-Test", "short " + token + " tail");
        string[] lines = folded.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.Contains(lines, l => l.Trim() == token);
    }

    [Fact]
    public void A_token_that_would_exceed_998_bytes_is_an_error()
    {
        Assert.Throws<MessageBuildException>(() => HeaderFolder.Fold("X-Test", new string('x', 1000)));
        Assert.Throws<MessageBuildException>(() => HeaderFolder.Fold("X-Test", new string('é', 600), allowNonAscii: true)); // 1200 bytes
    }

    [Theory]
    [InlineData("a\r\nb")]
    [InlineData("a\nb")]
    [InlineData("a\rb")]
    [InlineData("a\0b")]
    [InlineData("a\u0001b")]
    public void Control_characters_are_rejected(string value) => Assert.Throws<HeaderInjectionException>(() => HeaderFolder.Fold("X-Test", value));

    [Fact]
    public void Non_ascii_requires_opt_in()
    {
        Assert.Throws<HeaderInjectionException>(() => HeaderFolder.Fold("X-Test", "café"));
        Assert.Equal("X-Test: café\r\n", HeaderFolder.Fold("X-Test", "café", allowNonAscii: true));
    }

    [Theory]
    [InlineData("")]
    [InlineData("a b")]
    [InlineData("a:b")]
    [InlineData("a\r\nb")]
    [InlineData("a\0")]
    [InlineData("café")]
    public void Invalid_names_are_rejected(string name) => Assert.Throws<HeaderInjectionException>(() => HeaderValidator.ValidateName(name));

    [Fact]
    public void Exception_message_does_not_echo_control_characters()
    {
        var ex = Assert.Throws<HeaderInjectionException>(() => HeaderFolder.Fold("X-Te\r\nst", "v"));
        Assert.DoesNotContain('\r', ex.Message);
        Assert.DoesNotContain('\n', ex.Message);
        Assert.Equal("X-Te\r\nst", ex.HeaderName);
        Assert.NotEmpty(ex.Reason);
    }

    [Fact]
    public void Valid_names_pass()
    {
        foreach (string name in new[] { "From", "X-Custom-Header", "List-Unsubscribe-Post", "a", "X_1.2~3" })
        {
            HeaderValidator.ValidateName(name);
        }
    }
}
