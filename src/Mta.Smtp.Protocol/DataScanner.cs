using System.Buffers;

namespace Mta.Smtp.Protocol;

public enum DataScanStatus : byte
{
    /// <summary>All input consumed, terminator not seen yet.</summary>
    NeedMoreData,

    /// <summary>The end-of-data sequence <c>CRLF.CRLF</c> was found; remaining input after it was not consumed.</summary>
    Complete,

    /// <summary>A LF without CR (SMTP smuggling vector).</summary>
    BareLf,

    /// <summary>A CR not followed by LF.</summary>
    BareCr,

    /// <summary>A NUL byte, when rejected by options.</summary>
    Nul,
}

/// <summary>
/// Incremental DATA decoder (RFC 5321 §4.5.2): removes dot-stuffing and detects the end-of-data sequence while
/// refusing every non-CRLF line terminator, which is the defense against SMTP smuggling (CVE-2023-51764 family).
/// The scanner is resumable at any byte boundary (it keeps a tiny state between calls).
/// </summary>
public struct DataScanner
{
    private enum State : byte
    {
        LineStart,
        Normal,
        Cr,
        LineStartDot,
        LineStartDotCr,
    }

    private State _state;
    private readonly bool _rejectNul;

    public DataScanner(bool rejectNul = true)
    {
        _state = State.LineStart;
        _rejectNul = rejectNul;
    }

    /// <summary>Number of un-stuffed body bytes written to the output so far.</summary>
    public long BytesWritten { get; private set; }

    /// <summary>
    /// Processes <paramref name="input"/>, writing the unstuffed body (including the CRLF that precedes the final dot line)
    /// to <paramref name="output"/>. <paramref name="consumed"/> is the number of input bytes used.
    /// </summary>
    public DataScanStatus Scan(ReadOnlySpan<byte> input, IBufferWriter<byte> output, out int consumed)
    {
        int i = 0;
        int runStart = 0;
        while (i < input.Length)
        {
            switch (_state)
            {
                case State.LineStart:
                    if (input[i] == (byte)'.')
                    {
                        Flush(input, runStart, i, output);
                        _state = State.LineStartDot;
                        i++;
                        runStart = i;
                    }
                    else
                    {
                        _state = State.Normal;
                    }

                    break;

                case State.Normal:
                    {
                        int j = _rejectNul
                            ? input[i..].IndexOfAny((byte)'\r', (byte)'\n', (byte)0)
                            : input[i..].IndexOfAny((byte)'\r', (byte)'\n');
                        if (j < 0)
                        {
                            i = input.Length;
                            break;
                        }

                        i += j;
                        byte b = input[i];
                        if (b == '\r')
                        {
                            _state = State.Cr;
                            i++;
                        }
                        else if (b == '\n')
                        {
                            Flush(input, runStart, i, output);
                            consumed = i;
                            return DataScanStatus.BareLf;
                        }
                        else
                        {
                            Flush(input, runStart, i, output);
                            consumed = i;
                            return DataScanStatus.Nul;
                        }

                        break;
                    }

                case State.Cr:
                    if (input[i] == (byte)'\n')
                    {
                        _state = State.LineStart;
                        i++;
                    }
                    else
                    {
                        Flush(input, runStart, i, output);
                        consumed = i;
                        return DataScanStatus.BareCr;
                    }

                    break;

                case State.LineStartDot:
                    if (input[i] == (byte)'\r')
                    {
                        _state = State.LineStartDotCr;
                        i++;
                        runStart = i;
                    }
                    else
                    {
                        // The dot was stuffing (RFC 5321 §4.5.2): it is dropped and the line continues as ordinary text.
                        _state = State.Normal;
                    }

                    break;

                case State.LineStartDotCr:
                    if (input[i] == (byte)'\n')
                    {
                        Flush(input, runStart, i - 1, output);
                        consumed = i + 1;
                        _state = State.LineStart;
                        return DataScanStatus.Complete;
                    }

                    consumed = i;
                    return DataScanStatus.BareCr;
            }
        }

        Flush(input, runStart, input.Length, output);
        consumed = input.Length;
        return DataScanStatus.NeedMoreData;
    }

    private void Flush(ReadOnlySpan<byte> input, int from, int to, IBufferWriter<byte> output)
    {
        if (to > from)
        {
            output.Write(input[from..to]);
            BytesWritten += to - from;
        }
    }
}
