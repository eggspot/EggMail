using System.Diagnostics.Metrics;

namespace Mta.Webhooks;

/// <summary>Meters of the webhook dispatcher (<c>Mta.Webhooks</c>). Labels are small fixed sets: never an endpoint, a tenant or a URL.</summary>
public static class WebhookMetrics
{
    public static readonly Meter Meter = new("Mta.Webhooks");

    /// <summary>Delivery attempts by outcome: <c>delivered</c>, <c>retry</c> (failed, will be tried again) or <c>failed</c> (given up).</summary>
    public static readonly Counter<long> Deliveries = Meter.CreateCounter<long>("mta.webhooks.deliveries", "{attempt}", "Webhook delivery attempts by outcome (delivered, retry, failed)");

    /// <summary>Failed attempts by reason class (see <see cref="ReasonOf"/>).</summary>
    public static readonly Counter<long> Failures = Meter.CreateCounter<long>("mta.webhooks.failures", "{attempt}", "Failed webhook attempts by reason");

    /// <summary>Time of one HTTP call to a receiver, including the response snippet.</summary>
    public static readonly Histogram<double> DeliveryDuration = Meter.CreateHistogram<double>("mta.webhooks.delivery.duration", "s", "Duration of one webhook HTTP call");

    /// <summary>Endpoints switched off after a <c>410 Gone</c> or a continuous failure period.</summary>
    public static readonly Counter<long> EndpointsDisabled = Meter.CreateCounter<long>("mta.webhooks.endpoints.disabled", "{endpoint}", "Webhook endpoints disabled automatically");

    /// <summary>Outbox items claimed for delivery (the rate of work picked up).</summary>
    public static readonly Counter<long> Claimed = Meter.CreateCounter<long>("mta.webhooks.claimed", "{event}", "Webhook outbox items claimed for delivery");

    /// <summary>
    /// Folds an error class (<c>http_503</c>, <c>timeout</c>...) into a fixed set of reasons so the label stays bounded:
    /// <c>timeout</c>, <c>connect_failed</c>, <c>ssrf_blocked</c>, <c>throttled</c>, <c>gone</c>, <c>redirect</c>, <c>http_4xx</c>, <c>http_5xx</c>,
    /// <c>endpoint_unavailable</c>, <c>secret_unreadable</c> and <c>other</c>.
    /// </summary>
    public static string ReasonOf(string errorClass) => errorClass switch
    {
        "timeout" or "connect_failed" or "ssrf_blocked" or "throttled" or "gone" or "endpoint_unavailable" or "secret_unreadable" => errorClass,
        "redirect_not_followed" => "redirect",
        "http_error" => "other",
        _ when errorClass.StartsWith("http_", StringComparison.Ordinal) && errorClass.Length == 8 && errorClass[5] == '4' => "http_4xx",
        _ when errorClass.StartsWith("http_", StringComparison.Ordinal) && errorClass.Length == 8 && errorClass[5] == '5' => "http_5xx",
        _ => "other",
    };
}
