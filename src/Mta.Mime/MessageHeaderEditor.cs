using System.Buffers;
using System.Text;

namespace Mta.Mime;

/// <summary>
/// Edits the header block of a raw message without touching, parsing or copying the body more than once: prepend trace
/// and signature headers, remove or replace headers by name, append headers, and emit the result as a new buffer or into an
/// <see cref="IBufferWriter{T}"/>. Original header bytes are preserved exactly (folding, line endings, case); only
/// headers that match a rule change. Every header written is validated against injection (CR, LF, NUL).
/// </summary>
/// <remarks>
/// Order of prepended headers: each <c>Prepend</c> puts its header above the previous ones, so calling
/// <c>Prepend("Received")</c> and then <c>Prepend("Return-Path")</c> yields Return-Path first, then Received, then the original headers.
/// Rules apply to every header field in the block (there is no header count limit). An instance is not thread-safe.
/// </remarks>
public sealed class MessageHeaderEditor
{
    private readonly ReadOnlyMemory<byte> _message;
    private readonly List<byte[]> _prepended = [];
    private readonly List<byte[]> _appended = [];
    private readonly List<Rule> _rules = [];

    private sealed class Rule(string name)
    {
        public string Name { get; } = name;

        public byte[]? Replacement { get; set; }

        public bool Emitted { get; set; }
    }

    /// <summary>Creates an editor over <paramref name="message"/> (not copied until output).</summary>
    public MessageHeaderEditor(ReadOnlyMemory<byte> message) => _message = message;

    /// <summary>Adds <c>name: value</c> above all current headers. The value is folded at 78 columns.</summary>
    /// <exception cref="HeaderInjectionException">Name or value contains CR, LF, NUL or other control characters (or non-ASCII when not allowed).</exception>
    public MessageHeaderEditor Prepend(string name, string value, bool allowUtf8 = false)
    {
        _prepended.Add(Format(name, value, allowUtf8));
        return this;
    }

    /// <summary>
    /// Adds an already formatted (and folded) header field above all current headers, for example a DKIM-Signature.
    /// The bytes must be one complete field: <c>Name: value</c> lines ending in CRLF, continuation lines starting with
    /// space or tab, no bare CR or LF, no NUL and no empty line.
    /// </summary>
    /// <exception cref="HeaderInjectionException">The bytes are not exactly one well-formed header field.</exception>
    public MessageHeaderEditor PrependRaw(ReadOnlySpan<byte> field)
    {
        ValidateRawField(field);
        _prepended.Add(field.ToArray());
        return this;
    }

    /// <summary>Adds <c>name: value</c> after the last current header (just before the empty line).</summary>
    public MessageHeaderEditor Append(string name, string value, bool allowUtf8 = false)
    {
        _appended.Add(Format(name, value, allowUtf8));
        return this;
    }

    /// <summary>Adds an already formatted header field after the last current header; see <see cref="PrependRaw"/> for the format rules.</summary>
    public MessageHeaderEditor AppendRaw(ReadOnlySpan<byte> field)
    {
        ValidateRawField(field);
        _appended.Add(field.ToArray());
        return this;
    }

    /// <summary>Removes every header with this name (case-insensitive). Overrides an earlier <see cref="Replace"/> of the same name.</summary>
    public MessageHeaderEditor Remove(string name)
    {
        HeaderValidator.ValidateName(name);
        GetRule(name).Replacement = null;
        return this;
    }

    /// <summary>
    /// Replaces the first header with this name in place and removes any further ones. When the message has no such
    /// header, the new header is appended after the last header.
    /// </summary>
    public MessageHeaderEditor Replace(string name, string value, bool allowUtf8 = false)
    {
        GetRule(name).Replacement = Format(name, value, allowUtf8);
        return this;
    }

    /// <summary>Prepends a Received trace header (value as produced by the SMTP server).</summary>
    public MessageHeaderEditor PrependReceived(string value) => Prepend(HeaderNames.Received, value);

    /// <summary>Prepends <c>Return-Path: &lt;path&gt;</c> (pass the address without brackets; empty for the null path).</summary>
    public MessageHeaderEditor PrependReturnPath(string address) => Prepend(HeaderNames.ReturnPath, "<" + address + ">");

    /// <summary>Prepends an Authentication-Results header.</summary>
    public MessageHeaderEditor PrependAuthenticationResults(string value) => Prepend(HeaderNames.AuthenticationResults, value);

    /// <summary>The edited message as a new array.</summary>
    public byte[] ToArray()
    {
        // Build in a rented buffer and copy once into an exactly sized array (an ArrayBufferWriter plus ToArray would allocate the message twice).
        var writer = new RentedBufferWriter(_message.Length + 1024);
        try
        {
            WriteTo(writer);
            return writer.WrittenSpan.ToArray();
        }
        finally
        {
            writer.Dispose();
        }
    }

    private sealed class RentedBufferWriter(int initialCapacity) : IBufferWriter<byte>, IDisposable
    {
        private byte[] _buffer = ArrayPool<byte>.Shared.Rent(Math.Max(initialCapacity, 256));
        private int _written;

        public ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _written);

        public void Advance(int count) => _written += count;

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            Grow(sizeHint);
            return _buffer.AsMemory(_written);
        }

        public Span<byte> GetSpan(int sizeHint = 0)
        {
            Grow(sizeHint);
            return _buffer.AsSpan(_written);
        }

        private void Grow(int sizeHint)
        {
            int needed = _written + Math.Max(sizeHint, 1);
            if (needed <= _buffer.Length)
            {
                return;
            }

            byte[] bigger = ArrayPool<byte>.Shared.Rent(Math.Max(needed, _buffer.Length * 2));
            _buffer.AsSpan(0, _written).CopyTo(bigger);
            ArrayPool<byte>.Shared.Return(_buffer);
            _buffer = bigger;
        }

        public void Dispose() => ArrayPool<byte>.Shared.Return(_buffer);
    }

    /// <summary>Writes the edited message to <paramref name="writer"/> and returns the number of bytes written.</summary>
    public long WriteTo(IBufferWriter<byte> writer)
    {
        ArgumentNullException.ThrowIfNull(writer);
        var data = _message.Span;
        long total = 0;
        for (int i = _prepended.Count - 1; i >= 0; i--)
        {
            total += Put(writer, _prepended[i]);
        }

        foreach (var r in _rules)
        {
            r.Emitted = false;
        }

        int pos = 0;
        int blockEnd = 0;
        bool separator = false;
        while (pos < data.Length)
        {
            if (!HeaderList.TryReadField(data, pos, out int fieldEnd, out int next, out int nameLength, out bool blank, out _))
            {
                break;
            }

            if (blank)
            {
                separator = true;
                blockEnd = pos;
                break;
            }

            var name = data.Slice(pos, nameLength);
            Rule? rule = nameLength == 0 ? null : FindRule(name);
            if (rule is null)
            {
                total += Put(writer, data[pos..fieldEnd]);
                total += PutLineEnd(writer, data, fieldEnd, next);
            }
            else if (rule.Replacement is not null && !rule.Emitted)
            {
                rule.Emitted = true;
                total += Put(writer, rule.Replacement);
            }

            pos = next;
            blockEnd = next;
        }

        foreach (var r in _rules)
        {
            if (r.Replacement is not null && !r.Emitted)
            {
                total += Put(writer, r.Replacement);
            }
        }

        foreach (var a in _appended)
        {
            total += Put(writer, a);
        }

        if (separator)
        {
            total += Put(writer, data[blockEnd..]);
        }
        else
        {
            // No empty line: terminate the header block, with an empty body.
            total += Put(writer, "\r\n"u8);
        }

        return total;
    }

    private static long PutLineEnd(IBufferWriter<byte> writer, ReadOnlySpan<byte> data, int fieldEnd, int next)
    {
        // Preserve the original line ending; add CRLF to an unterminated final line so the next header starts on its own line.
        if (next > fieldEnd)
        {
            return Put(writer, data[fieldEnd..next]);
        }

        return Put(writer, "\r\n"u8);
    }

    private Rule GetRule(string name)
    {
        HeaderValidator.ValidateName(name);
        foreach (var r in _rules)
        {
            if (string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase))
            {
                return r;
            }
        }

        var rule = new Rule(name);
        _rules.Add(rule);
        return rule;
    }

    private Rule? FindRule(ReadOnlySpan<byte> name)
    {
        foreach (var r in _rules)
        {
            if (System.Text.Ascii.EqualsIgnoreCase(name, r.Name))
            {
                return r;
            }
        }

        return null;
    }

    private static long Put(IBufferWriter<byte> writer, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > 0)
        {
            LineEndings.Write(writer, bytes);
        }

        return bytes.Length;
    }

    private static byte[] Format(string name, string value, bool allowUtf8)
    {
        var sb = new StringBuilder(name.Length + value.Length + 8);
        HeaderFolder.AppendField(sb, name, value, allowUtf8);
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private static void ValidateRawField(ReadOnlySpan<byte> field)
    {
        const string Who = "raw header";
        if (field.Length < 4 || field[^1] != (byte)'\n' || field[^2] != (byte)'\r')
        {
            throw new HeaderInjectionException(Who, "a raw header must end with CRLF");
        }

        int pos = 0;
        bool first = true;
        while (pos < field.Length)
        {
            int nl = field[pos..].IndexOf((byte)'\n');
            if (nl < 1 || field[pos + nl - 1] != (byte)'\r')
            {
                throw new HeaderInjectionException(Who, "a raw header must use CRLF line endings only");
            }

            var line = field.Slice(pos, nl - 1);
            if (line.IndexOf((byte)'\r') >= 0 || line.IndexOf((byte)0) >= 0)
            {
                throw new HeaderInjectionException(Who, "a raw header must not contain bare CR or NUL");
            }

            if (line.IsEmpty)
            {
                throw new HeaderInjectionException(Who, "a raw header must not contain an empty line");
            }

            if (first)
            {
                int colon = line.IndexOf((byte)':');
                if (colon <= 0)
                {
                    throw new HeaderInjectionException(Who, "a raw header must start with a field name and a colon");
                }

                for (int i = 0; i < colon; i++)
                {
                    if (line[i] <= 32 || line[i] >= 127)
                    {
                        throw new HeaderInjectionException(Who, "invalid character in the field name");
                    }
                }

                first = false;
            }
            else if (line[0] is not ((byte)' ' or (byte)'\t'))
            {
                throw new HeaderInjectionException(Who, "continuation lines of a raw header must start with space or tab");
            }

            pos += nl + 1;
        }
    }
}
