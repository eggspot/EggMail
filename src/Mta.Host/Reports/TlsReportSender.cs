using Mta.Core;
using Mta.Mime;
using Mta.Storage;
using Mta.Tls.TlsRpt;

namespace Mta.Host.Reports;

/// <summary>
/// Sends the daily TLS-RPT reports (RFC 8460) for the domains whose MTA-STS or DANE policy applied to our outbound sessions:
/// looks up the domain's <c>_smtp._tls</c> record and sends to the first endpoint that accepts (HTTPS POST, or an e-mail queued
/// through the normal delivery pipeline). A report that could not be delivered is kept in memory and retried on later runs
/// (up to <see cref="MaxAttempts"/>); a restart loses pending reports, which is acceptable for aggregate statistics.
/// </summary>
public sealed class TlsReportSender
{
    public const int MaxAttempts = 6;

    private sealed record Pending(TlsRptDomainReportData Data, int Attempts);

    private readonly TlsRptCollector _collector;
    private readonly TlsRptRecordLookup _lookup;
    private readonly TlsRptHttpsSender _https;
    private readonly TlsRptReportBuilder _builder;
    private readonly IMessageIntake _intake;
    private readonly IClock _clock;
    private readonly string _hostname;
    private readonly IMtaLog _log;
    private readonly List<Pending> _retry = [];

    public TlsReportSender(TlsRptCollector collector, TlsRptRecordLookup lookup, TlsRptHttpsSender https, IMessageIntake intake, IClock clock, string hostname, string contact, IMtaLog? log = null)
    {
        _collector = collector;
        _lookup = lookup;
        _https = https;
        _intake = intake;
        _clock = clock;
        _hostname = hostname;
        _log = log ?? NullMtaLog.Instance;
        _builder = new TlsRptReportBuilder(new TlsRptReportOptions { OrganizationName = hostname, ContactInfo = contact, SubmitterDomain = hostname });
    }

    /// <summary>Sends the reports of every completed UTC day (and retries earlier failures). Returns the number of reports sent.</summary>
    public async Task<int> RunOnceAsync(CancellationToken ct)
    {
        var work = _collector.DrainCompletedDays().Select(d => new Pending(d, 0)).Concat(Take()).ToList();
        int sent = 0;
        foreach (var item in work)
        {
            SendResult result;
            try
            {
                result = await SendAsync(item.Data, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.Write(MtaLogLevel.Warning, "tlsrpt", $"report for {item.Data.PolicyDomain} failed", ex);
                result = SendResult.Failed;
            }

            if (result == SendResult.Sent)
            {
                sent++;
            }
            else if (result == SendResult.Failed && item.Attempts + 1 < MaxAttempts)
            {
                _retry.Add(item with { Attempts = item.Attempts + 1 });
            }
        }

        return sent;
    }

    private List<Pending> Take()
    {
        var items = _retry.ToList();
        _retry.Clear();
        return items;
    }

    private enum SendResult { Sent, NothingToSend, Failed }

    private async Task<SendResult> SendAsync(TlsRptDomainReportData data, CancellationToken ct)
    {
        var record = await _lookup.LookupAsync(data.PolicyDomain, ct).ConfigureAwait(false);
        if (record is null)
        {
            return SendResult.NothingToSend;   // the domain asks for no reports (or stopped asking): nothing to retry
        }

        var report = _builder.Build(data);
        foreach (var endpoint in record.Endpoints)
        {
            if (endpoint.Kind == TlsRptEndpointKind.Https)
            {
                if ((await _https.SendAsync(endpoint, report, ct).ConfigureAwait(false)).Success)
                {
                    return SendResult.Sent;
                }
            }
            else if (endpoint.MailtoAddress is { } to && await QueueMailAsync(to, report, ct).ConfigureAwait(false))
            {
                return SendResult.Sent;
            }
        }

        return SendResult.Failed;
    }

    private async Task<bool> QueueMailAsync(string to, TlsRptReport report, CancellationToken ct)
    {
        if (!EmailAddress.TryParse(to, allowUtf8: false, out var recipient))
        {
            return false;
        }

        var now = _clock.UtcNow;
        var from = Mailbox.Create("TLS-RPT", "tls-rpt@" + _hostname);
        var builder = new MessageBuilder(new MessageBuilderOptions { MessageIdDomain = _hostname, Clock = _clock }) { From = from };
        builder.To.Add(Mailbox.Create(null, to));
        builder.Subject = $"Report Domain: {report.PolicyDomain} Submitter: {_hostname} Report-ID: <{report.ReportId}>";
        builder.TextBody = "This is an aggregate TLS report from " + _hostname + ".\r\n";
        builder.Attachments.Add(new BuilderAttachment(report.FileName, TlsRptReport.GzipMediaType, report.GzipPayload));
        builder.AddHeader("TLS-Report-Domain", report.PolicyDomain);
        builder.AddHeader("TLS-Report-Submitter", _hostname);
        var (raw, _) = builder.Build();

        await _intake.AcceptAsync(new AcceptedMessage
        {
            MessageId = Ids.New(now),
            TenantId = Guid.Empty,
            Source = MessageSource.System,
            EnvelopeFrom = from.Address,
            Recipients = [new AcceptedRecipient(Ids.New(now), recipient)],
            Raw = raw,
            ReceivedAt = now,
            ExpiresAt = now.AddDays(2),
        }, ct).ConfigureAwait(false);
        return true;
    }
}
