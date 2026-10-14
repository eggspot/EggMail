using Mta.Host.Configuration;

namespace Mta.Host.Tests;

public class ObservabilityConfigTests
{
    private static List<string> Errors(ObservabilitySection section)
    {
        var errors = new List<string>();
        ConfigLoader.Validate(new MtaConfig { Observability = section }, errors);
        return errors.Where(e => e.StartsWith("Observability:", StringComparison.Ordinal)).ToList();
    }

    [Theory]
    [InlineData("http://collector:4317")]
    [InlineData("https://otel.example.com")]
    [InlineData("http://127.0.0.1:4318/")]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("  ")]
    public void A_usable_or_absent_endpoint_is_accepted(string? endpoint) =>
        Assert.Empty(Errors(new ObservabilitySection { OtlpEndpoint = endpoint }));

    [Theory]
    [InlineData("collector:4317")]       // parses as scheme "collector"
    [InlineData("collector")]
    [InlineData("localhost:4317")]
    [InlineData("grpc://collector:4317")]
    [InlineData("ftp://collector")]
    [InlineData("file:///tmp/x")]
    public void An_endpoint_without_an_http_or_https_scheme_is_refused(string endpoint)
    {
        string error = Assert.Single(Errors(new ObservabilitySection { OtlpEndpoint = endpoint }));
        Assert.Contains("Observability:OtlpEndpoint", error);
        Assert.Contains("http or https", error);
    }

    [Theory]
    [InlineData("Grpc", true)]
    [InlineData("grpc", true)]
    [InlineData("HttpProtobuf", true)]
    [InlineData("Http", false)]
    [InlineData("", false)]
    public void The_protocol_must_be_one_of_the_two(string protocol, bool valid) =>
        Assert.Equal(valid, Errors(new ObservabilitySection { OtlpProtocol = protocol }).Count == 0);

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(0.25, true)]
    [InlineData(-0.1, false)]
    [InlineData(1.5, false)]
    [InlineData(double.NaN, false)]
    public void The_trace_ratio_is_between_zero_and_one(double ratio, bool valid) =>
        Assert.Equal(valid, Errors(new ObservabilitySection { TraceSampleRatio = ratio }).Count == 0);

    [Theory]
    [InlineData(0, true)]
    [InlineData(15, true)]
    [InlineData(3600, true)]
    [InlineData(-1, false)]
    [InlineData(3601, false)]
    public void The_queue_sample_interval_is_zero_or_up_to_an_hour(int seconds, bool valid) =>
        Assert.Equal(valid, Errors(new ObservabilitySection { QueueSampleSeconds = seconds }).Count == 0);
}
