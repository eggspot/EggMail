namespace Mta.Host.Tests;

public class CliTests
{
    [Fact]
    public void The_command_is_taken_out_once_and_option_values_equal_to_it_survive()
    {
        // Regression: `admin create --role admin --user admin` lost both "admin" values (every argument equal to the command was removed).
        (string command, string[] rest) = Cli.SplitCommand(["admin", "create", "--role", "admin", "--user", "admin"]);

        Assert.Equal("admin", command);
        Assert.Equal(["create", "--role", "admin", "--user", "admin"], rest);
    }

    [Fact]
    public void No_command_means_serve_and_options_are_kept()
    {
        (string command, string[] rest) = Cli.SplitCommand(["--Dashboard:HttpPort=9000"]);

        Assert.Equal("serve", command);
        Assert.Equal(["--Dashboard:HttpPort=9000"], rest);
    }

    [Fact]
    public void Flag_style_commands_are_recognized()
    {
        Assert.Equal("--healthcheck", Cli.SplitCommand(["--healthcheck", "--Dashboard:HttpPort=9000"]).Command);
        Assert.Equal("--version", Cli.SplitCommand(["--version"]).Command);
    }
}
