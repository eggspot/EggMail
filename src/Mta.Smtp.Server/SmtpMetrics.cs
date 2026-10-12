using System.Diagnostics.Metrics;

namespace Mta.Smtp.Server;

/// <summary>System.Diagnostics.Metrics instruments of the SMTP server (BCL; exported by the host's OpenTelemetry setup).</summary>
public static class SmtpMetrics
{
    public static readonly Meter Meter = new("Mta.Smtp.Server");

    public static readonly Counter<long> Connections = Meter.CreateCounter<long>("mta.smtp.server.connections", "{connection}", "Accepted connections");
    public static readonly Counter<long> RefusedConnections = Meter.CreateCounter<long>("mta.smtp.server.connections.refused", "{connection}", "Connections refused by limits or policy");
    public static readonly Counter<long> Messages = Meter.CreateCounter<long>("mta.smtp.server.messages", "{message}", "Messages accepted (250)");
    public static readonly Counter<long> MessagesRejected = Meter.CreateCounter<long>("mta.smtp.server.messages.rejected", "{message}", "Messages refused after DATA");
    public static readonly Counter<long> Bytes = Meter.CreateCounter<long>("mta.smtp.server.bytes", "By", "Message bytes accepted");
    public static readonly Counter<long> Commands = Meter.CreateCounter<long>("mta.smtp.server.commands", "{command}", "Commands processed");
    public static readonly Counter<long> ProtocolErrors = Meter.CreateCounter<long>("mta.smtp.server.protocol_errors", "{error}", "Protocol violations (bad syntax/sequence, smuggling attempts)");
    public static readonly Counter<long> TlsHandshakes = Meter.CreateCounter<long>("mta.smtp.server.tls.handshakes", "{handshake}", "Completed TLS handshakes");
    public static readonly Counter<long> TlsFailures = Meter.CreateCounter<long>("mta.smtp.server.tls.failures", "{handshake}", "Failed TLS handshakes");
    public static readonly Counter<long> AuthFailures = Meter.CreateCounter<long>("mta.smtp.server.auth.failures", "{attempt}", "Failed AUTH attempts");
    public static readonly Histogram<double> TransactionSeconds = Meter.CreateHistogram<double>("mta.smtp.server.transaction.duration", "s", "Time from end of DATA to final reply");
    public static readonly UpDownCounter<long> ActiveSessions = Meter.CreateUpDownCounter<long>("mta.smtp.server.sessions.active", "{session}", "Open sessions");
}
