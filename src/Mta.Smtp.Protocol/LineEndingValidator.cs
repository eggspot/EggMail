namespace Mta.Smtp.Protocol;

/// <summary>What <see cref="LineEndingValidator"/> found.</summary>
public enum LineEndingStatus : byte
{
    /// <summary>Everything seen so far is well formed.</summary>
    Ok,

    /// <summary>A LF that is not preceded by CR.</summary>
    BareLf,

    /// <summary>A CR that is not followed by LF.</summary>
    BareCr,

    /// <summary>A NUL byte, when rejected by options.</summary>
    Nul,
}

/// <summary>
/// Applies to a body that arrives in pieces without a terminator to scan for (<c>BDAT</c> chunks) the same rule <see cref="DataScanner"/> applies to
/// <c>DATA</c>: every line ends with CRLF, nothing else, and there is no NUL. The messages are sent on to other servers with DATA, and a bare LF
/// in them is the raw material of SMTP smuggling at the next hop; the outbound client refuses such a message, so accepting it here would only
/// postpone the failure to a bounce. The validator keeps one bit of state, so chunk boundaries (even between the CR and the LF) do not matter.
/// </summary>
public sealed class LineEndingValidator
{
    private readonly bool _rejectNul;
    private bool _afterCr;

    public LineEndingValidator(bool rejectNul = true)
    {
        _rejectNul = rejectNul;
    }

    /// <summary>Checks the next piece of the body. After a failure the validator must not be used again.</summary>
    public LineEndingStatus Check(ReadOnlySpan<byte> data)
    {
        int i = 0;
        while (i < data.Length)
        {
            if (_afterCr)
            {
                if (data[i] != (byte)'\n')
                {
                    return LineEndingStatus.BareCr;
                }

                _afterCr = false;
                i++;
                continue;
            }

            int found = _rejectNul
                ? data[i..].IndexOfAny((byte)'\r', (byte)'\n', (byte)0)
                : data[i..].IndexOfAny((byte)'\r', (byte)'\n');
            if (found < 0)
            {
                return LineEndingStatus.Ok;
            }

            i += found;
            switch (data[i])
            {
                case (byte)'\n':
                    return LineEndingStatus.BareLf;
                case 0:
                    return LineEndingStatus.Nul;
                default:
                    _afterCr = true;
                    i++;
                    break;
            }
        }

        return LineEndingStatus.Ok;
    }

    /// <summary>Call after the last piece: a CR at the very end has no LF after it.</summary>
    public LineEndingStatus Complete() => _afterCr ? LineEndingStatus.BareCr : LineEndingStatus.Ok;
}
