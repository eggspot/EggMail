using System.Text;

namespace Mta.RemoteMta.Tests.Harness;

/// <summary>What a fake remote MTA does in answer to something the delivering side did: a reply, garbage, silence, or a dropped connection.</summary>
public sealed class Step
{
    internal enum Kind { Reply, Raw, Close, Abort, Hang, Gated, Drip, Sequence }

    internal Kind What { get; private init; }
    internal int Code { get; private init; }
    internal string? Enhanced { get; private init; }
    internal string[] Lines { get; private init; } = [];
    internal byte[] Bytes { get; private init; } = [];
    internal Task? Gate { get; private init; }
    internal Step[] Steps { get; private init; } = [];
    internal int ChunkSize { get; private init; }

    /// <summary>A reply; several <paramref name="lines"/> make a multi-line reply (<c>250-</c> continuation lines). The enhanced status code is left out when the personality does not advertise ENHANCEDSTATUSCODES.</summary>
    public static Step Reply(int code, string? enhanced, params string[] lines) => new() { What = Kind.Reply, Code = code, Enhanced = enhanced, Lines = lines.Length == 0 ? [string.Empty] : lines };

    /// <summary>Bytes sent exactly as given (a malformed or hostile peer).</summary>
    public static Step Raw(string text) => new() { What = Kind.Raw, Bytes = Encoding.Latin1.GetBytes(text) };

    public static Step RawBytes(byte[] bytes) => new() { What = Kind.Raw, Bytes = bytes };

    /// <summary>Closes the connection without saying anything (a FIN).</summary>
    public static Step Close() => new() { What = Kind.Close };

    /// <summary>Resets the connection (an RST), as a crashed or firewalled peer does.</summary>
    public static Step Abort() => new() { What = Kind.Abort };

    /// <summary>Says nothing and keeps the connection open until the other side gives up or the server is disposed.</summary>
    public static Step Hang() => new() { What = Kind.Hang };

    /// <summary>Waits for the test to complete <paramref name="gate"/>, then does <paramref name="then"/>. This is how a "slow" peer is made without sleeping.</summary>
    public static Step After(Task gate, Step then) => new() { What = Kind.Gated, Gate = gate, Steps = [then] };

    /// <summary>Sends <paramref name="text"/> a few bytes at a time (a tarpit that does finish).</summary>
    public static Step Drip(string text, int chunkSize = 1) => new() { What = Kind.Drip, Bytes = Encoding.Latin1.GetBytes(text), ChunkSize = Math.Max(1, chunkSize) };

    public static Step Sequence(params Step[] steps) => new() { What = Kind.Sequence, Steps = steps };

    /// <summary>This step, then <paramref name="next"/>.</summary>
    public Step Then(Step next) => Sequence(this, next);

    /// <summary>True when the first reply of this step is a positive completion (a 2xx).</summary>
    internal bool IsPositive => What switch
    {
        Kind.Reply => Code is >= 200 and < 300,
        Kind.Gated or Kind.Sequence => Steps.Length > 0 && Steps[0].IsPositive,
        _ => false,
    };

    internal string Format(bool enhancedStatusCodes)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < Lines.Length; i++)
        {
            sb.Append(Code).Append(i == Lines.Length - 1 ? ' ' : '-');
            if (enhancedStatusCodes && Enhanced is not null)
            {
                sb.Append(Enhanced).Append(' ');
            }

            sb.Append(Lines[i]).Append("\r\n");
        }

        return sb.ToString();
    }
}
