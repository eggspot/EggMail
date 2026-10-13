using System.Buffers;
using Mta.Core;
using Mta.Dkim;
using Mta.Mime;
using Mta.Smtp.Client;
using Mta.Smtp.Protocol;

namespace Mta.Delivery;

/// <summary>What an <see cref="OutboundTransaction"/> decided for one particular server.</summary>
/// <param name="Envelope">The envelope to send, or null when nothing can be sent to this server (see <see cref="WholeRefusal"/>).</param>
/// <param name="Message">The bytes to transmit: DKIM-signed over exactly these bytes, downgraded to 7-bit when the server cannot take 8-bit.</param>
/// <param name="WholeRefusal">Why this server cannot be sent this message at all; permanent, but another server of the domain may differ.</param>
/// <param name="RecipientRefusals">Recipients left out of <see cref="Envelope"/> because this server cannot take their address; permanent for them.</param>
internal sealed record Transmission(
    SmtpEnvelope? Envelope,
    ReadOnlyMemory<byte> Message,
    SmtpReply? WholeRefusal,
    IReadOnlyDictionary<EmailAddress, SmtpReply>? RecipientRefusals);

/// <summary>
/// One SMTP transaction of the delivery processor: a stored message, its envelope and the DKIM signer. What is actually put on the
/// wire depends on the server that answers (RFC 6152 8BITMIME, RFC 6531 SMTPUTF8), so the bytes are decided per connection by
/// <see cref="Plan"/> once the server's capabilities are known: an 8-bit body is declared <c>BODY=8BITMIME</c> when the server offers it
/// and is converted to 7-bit when it does not; SMTPUTF8 is declared when the headers or an address need it and the transaction is
/// refused cleanly when the server lacks it. DKIM is signed here, over the final bytes, because a downgrade changes the body and the
/// transfer-encoding headers and would invalidate a signature made before it. Each variant is built at most once per transaction.
/// </summary>
internal sealed class OutboundTransaction : IDisposable
{
    private readonly byte[] _raw;
    private readonly DkimSigner? _signer;
    private readonly List<byte[]> _rented = [];
    private readonly bool _bodyEightBit;
    private ReadOnlyMemory<byte>? _asStored;
    private ReadOnlyMemory<byte>? _downgraded;
    private string? _downgradeFailure;

    public OutboundTransaction(byte[] raw, DkimSigner? signer, bool headersUtf8Stored, EmailAddress from, IReadOnlyList<EmailAddress> recipients)
    {
        _raw = raw;
        _signer = signer;
        From = from;
        Recipients = recipients;
        HeadersUtf8 = headersUtf8Stored || MessageInspector.HasValidUtf8Headers(raw);
        _bodyEightBit = MessageInspector.HasEightBitBody(raw);
    }

    public EmailAddress From { get; }

    public IReadOnlyList<EmailAddress> Recipients { get; }

    /// <summary>The header section holds valid UTF-8 (RFC 6532): every server that gets this message must offer SMTPUTF8.</summary>
    public bool HeadersUtf8 { get; }

    /// <summary>The body has bytes above 0x7F: BODY=8BITMIME if the server has it, else a conversion to 7-bit.</summary>
    public bool BodyEightBit => _bodyEightBit;

    public Transmission Plan(SmtpCapabilities caps)
    {
        if (HeadersUtf8 && !caps.SmtpUtf8)
        {
            return Refused(SmtpReply.Create(554, "5.6.9", "the message has internationalized (UTF-8) header fields and the receiving server does not support SMTPUTF8 (RFC 6531); it cannot be delivered there"));
        }

        if (From.RequiresSmtpUtf8 && !caps.SmtpUtf8)
        {
            return Refused(SmtpReply.Create(553, "5.6.7", "the sender address is internationalized and the receiving server does not support SMTPUTF8 (RFC 6531)"));
        }

        var sendable = Recipients;
        Dictionary<EmailAddress, SmtpReply>? refusals = null;
        if (!caps.SmtpUtf8 && Recipients.Any(r => r.RequiresSmtpUtf8))
        {
            refusals = [];
            var keep = new List<EmailAddress>(Recipients.Count);
            foreach (var r in Recipients)
            {
                if (r.RequiresSmtpUtf8)
                {
                    refusals[r] = SmtpReply.Create(553, "5.6.7", "the recipient address is internationalized and the receiving server does not support SMTPUTF8 (RFC 6531)");
                }
                else
                {
                    keep.Add(r);
                }
            }

            if (keep.Count == 0)
            {
                return Refused(refusals.Values.First());
            }

            sendable = keep;
        }

        bool smtpUtf8 = HeadersUtf8 || From.RequiresSmtpUtf8 || sendable.Any(r => r.RequiresSmtpUtf8);
        bool eightBit = _bodyEightBit && caps.EightBitMime;
        ReadOnlyMemory<byte> message;
        if (_bodyEightBit && !caps.EightBitMime)
        {
            var downgraded = Downgraded();
            if (downgraded is null)
            {
                return Refused(SmtpReply.Create(554, "5.6.1", "the receiving server does not support 8BITMIME and the message cannot be converted to 7-bit: " + _downgradeFailure));
            }

            message = downgraded.Value;
        }
        else
        {
            message = AsStored();
        }

        return new Transmission(new SmtpEnvelope(From, sendable, smtpUtf8, eightBit), message, null, refusals);
    }

    private static Transmission Refused(SmtpReply reply) => new(null, default, reply, null);

    private ReadOnlyMemory<byte> AsStored() => _asStored ??= Finish(_raw);

    private ReadOnlyMemory<byte>? Downgraded()
    {
        if (_downgraded is not null || _downgradeFailure is not null)
        {
            return _downgraded;
        }

        var writer = new ArrayBufferWriter<byte>(_raw.Length + (_raw.Length >> 2) + 1024);
        var result = EightBitDowngrader.Downgrade(_raw, writer);
        switch (result.Status)
        {
            case EightBitDowngradeStatus.Downgraded:
                _downgraded = Finish(writer.WrittenMemory);
                break;
            case EightBitDowngradeStatus.NotNeeded:
                _downgraded = AsStored();
                break;
            default:
                _downgradeFailure = result.Reason ?? "no safe conversion exists";
                break;
        }

        return _downgraded;
    }

    /// <summary>Signs the final bytes (the signature field goes in front) or returns them unchanged when the sender has no key.</summary>
    private ReadOnlyMemory<byte> Finish(ReadOnlyMemory<byte> body)
    {
        if (_signer is null)
        {
            return body;
        }

        var signature = _signer.SignToBytes(body.Span);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(signature.Length + body.Length);
        _rented.Add(buffer);
        signature.Span.CopyTo(buffer);
        body.Span.CopyTo(buffer.AsSpan(signature.Length));
        return buffer.AsMemory(0, signature.Length + body.Length);
    }

    public void Dispose()
    {
        foreach (byte[] buffer in _rented)
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        _rented.Clear();
    }
}
