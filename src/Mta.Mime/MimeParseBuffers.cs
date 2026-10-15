namespace Mta.Mime;

/// <summary>
/// Working memory that one caller can lend to <see cref="MimeMessage.Parse(ReadOnlyMemory{byte}, MimeLimits?, MimeParseBuffers?)"/> so that parsing a message
/// does not allocate the record array of the top-level header block (about 250 bytes for an ordinary message) every time.
/// <para>
/// <b>Lifetime.</b> A message parsed with a buffer set is valid only until that buffer set is used for the next parse or released: its
/// <see cref="MimeMessage.Headers"/> read the buffer's array. Everything a caller keeps after that (strings, extracted content, the byte arrays of
/// an editor) is a copy and is not affected; the parsed objects themselves must not be kept. <see cref="Release"/> clears the records so that the
/// buffer does not hold on to the memory of the last message. One buffer set belongs to one caller at a time and is not thread safe.
/// </para>
/// </summary>
public sealed class MimeParseBuffers
{
    // A buffer for a hostile header block (thousands of fields) is not worth keeping.
    private const int MaxKeptRecords = 512;

    private MimeHeader[] _headers = [];
    private int _used;

    /// <summary>An array with at least <paramref name="capacity"/> slots for the top-level header records (its contents are unspecified).</summary>
    internal MimeHeader[] Headers(int capacity)
    {
        if (_headers.Length < capacity)
        {
            _headers = new MimeHeader[Math.Max(capacity, 32)];
        }

        _used = capacity;
        return _headers;
    }

    /// <summary>Call when the parsed message is no longer needed: drops the references the records hold and forgets an oversized array.</summary>
    public void Release()
    {
        if (_headers.Length > MaxKeptRecords)
        {
            _headers = [];
        }
        else
        {
            Array.Clear(_headers);   // all of it, not just what the last parse asked for: nothing of an earlier message may stay behind
        }

        _used = 0;
    }
}
