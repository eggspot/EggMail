namespace Mta.Mime;

/// <summary>The MIME-Version header (RFC 2045 section 4): <c>1.0</c>, possibly with comments and white space around the parts.</summary>
/// <param name="Major">Major version number.</param>
/// <param name="Minor">Minor version number.</param>
public readonly record struct MimeVersion(int Major, int Minor)
{
    /// <summary>Version 1.0, the only defined version.</summary>
    public static MimeVersion Version10 { get; } = new(1, 0);

    /// <summary>True for 1.0.</summary>
    public bool IsSupported => Major == 1 && Minor == 0;

    /// <summary>Parses a MIME-Version value. Returns false when it is not of the form <c>digits "." digits</c>.</summary>
    public static bool TryParse(ReadOnlySpan<char> value, out MimeVersion version)
    {
        version = default;
        int pos = 0;
        FieldScanner.SkipCfws(value, ref pos);
        if (!ReadNumber(value, ref pos, out int major))
        {
            return false;
        }

        FieldScanner.SkipCfws(value, ref pos);
        if (pos >= value.Length || value[pos] != '.')
        {
            return false;
        }

        pos++;
        FieldScanner.SkipCfws(value, ref pos);
        if (!ReadNumber(value, ref pos, out int minor))
        {
            return false;
        }

        FieldScanner.SkipCfws(value, ref pos);
        if (pos != value.Length)
        {
            return false;
        }

        version = new MimeVersion(major, minor);
        return true;
    }

    /// <summary>Parses a MIME-Version value.</summary>
    public static bool TryParse(string? value, out MimeVersion version)
    {
        if (value is null)
        {
            version = default;
            return false;
        }

        return TryParse(value.AsSpan(), out version);
    }

    /// <inheritdoc />
    public override string ToString() => string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{Major}.{Minor}");

    private static bool ReadNumber(ReadOnlySpan<char> value, ref int pos, out int number)
    {
        int start = pos;
        number = 0;
        while (pos < value.Length && char.IsAsciiDigit(value[pos]))
        {
            if (pos - start >= 4)
            {
                return false;
            }

            number = (number * 10) + (value[pos] - '0');
            pos++;
        }

        return pos > start;
    }
}
