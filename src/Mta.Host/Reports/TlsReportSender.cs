using Mta.Core;
using Mta.Mime;
using Mta.Storage;
using Mta.Tls.TlsRpt;

namespace Mta.Host.Reports;

/// <summary>
/// Sends the daily TLS-RPT reports (RFC 8460) for the domains whose MTA-STS or DANE policy applied to our outbound sessions:
/// looks up the domain's <c>_smtp._tls</c> record and sends to the first endpoint that accepts (HTTPS POST, or an e-mail queued
/// through the normal delivery pipeline). The counters of completed days come from the persisted journal (<see cref="TlsReportJournal"/>),
/// so a restart loses neither the counters nor a report that could not be delivered yet: a failed report keeps its (merged) counters and is
/// retried on later runs (up to <see cref="MaxAttempts"/>). A run takes a lease of the config store, so with several replicas on one database
/// each report is sent once.
/// </summary>
public sealed class TlsReportSender
{
    public const int MaxAttempts = 6;

    /// <summary>The most persisted counter pieces one run reads; the rest is handled by the next run.</summary>
    private const int MaxBucketsPerRun = 20_000;

    private const string LeaseName = "tls-rpt-sender";

    private readonly TlsReportJournal _journal;
    private readonly IConfigStore _config;
    private readonly string _owner = "tls-rpt-" + Guid.NewGuid().ToString("N");
    private readonly TlsRptRecordLookup _lookup;
    private readonly TlsRptHttpsSender _https;
    private readonly TlsRptReportBuilder _builder;
    private readonly IMessageIntake _intake;
    private readonly IClock _clock;
    private readonly string _hostname;
    private readonly IMtaLog _log;

    public TlsReportSender(TlsReportJournal journal, IConfigStore config, TlsRptRecordLookup lookup, TlsRptHttpsSender https, IMessageIntake intake, IClock clock, string hostname, string contact, IMtaLog? log = null)
    {
        _journal = journal;
        _config = config;
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
        await _journal.FlushAsync(ct).ConfigureAwait(false);   // what the collector holds for the days that just ended
        if (await _config.TryAcquireLeaseAsync(LeaseName, _owner, TimeSpan.FromMinutes(30), _clock.UtcNow, ct).ConfigureAwait(false) is null)
        {
            return 0;   // another replica is sending
        }

        try
        {
            int sent = 0;
            foreach (var item in await _journal.GetCompletedAsync(MaxBucketsPerRun, ct).ConfigureAwait(false))
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

                if (result == SendResult.Failed)
                {
                    await _journal.RetryLaterAsync(item, giveUp: item.Attempts + 1 >= MaxAttempts, ct).ConfigureAwait(false);
                    continue;
                }

                await _journal.CompleteAsync(item, ct).ConfigureAwait(false);
                if (result == SendResult.Sent)
                {
                    sent++;
                }
            }

            return sent;
        }
        finally
        {
            await _config.ReleaseLeaseAsync(LeaseName, _owner, CancellationToken.None).ConfigureAwait(false);
        }
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
