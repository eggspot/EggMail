using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace Mta.Host.Api;

/// <summary>Timestamps on the wire: ISO 8601 UTC with milliseconds (<c>2026-10-12T08:00:00.000Z</c>).</summary>
internal sealed class UtcTimestampConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String
            && DateTimeOffset.TryParse(reader.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value))
        {
            return value;
        }

        throw new JsonException("Not a valid ISO 8601 timestamp.");
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
}

/// <summary>Ids on the wire: 32 lower-case hex digits, no hyphens.</summary>
internal sealed class CompactGuidConverter : JsonConverter<Guid>
{
    public override Guid Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String && Guid.TryParse(reader.GetString(), out Guid id))
        {
            return id;
        }

        throw new JsonException("Not a valid id.");
    }

    public override void Write(Utf8JsonWriter writer, Guid value, JsonSerializerOptions options) => writer.WriteStringValue(value.ToString("N", CultureInfo.InvariantCulture));
}

/// <summary>JSON settings shared by every endpoint.</summary>
public static class ApiJson
{
    /// <summary>Responses: camelCase members (snake_case where the contract says so, via attributes), nulls written, ids and timestamps in the wire formats.</summary>
    public static readonly JsonSerializerOptions Write = Create(strict: false);

    /// <summary>Requests: unknown members are an error (<c>validation_failed</c>), numbers must be numbers, depth is bounded.</summary>
    public static readonly JsonSerializerOptions Read = Create(strict: true);

    private static JsonSerializerOptions Create(bool strict)
    {
        var o = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            PropertyNameCaseInsensitive = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.Never,
            MaxDepth = 32,
            WriteIndented = false,
        };
        o.Converters.Add(new UtcTimestampConverter());
        o.Converters.Add(new CompactGuidConverter());
        if (strict)
        {
            o.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
            o.NumberHandling = JsonNumberHandling.Strict;
            o.AllowTrailingCommas = false;
            o.ReadCommentHandling = JsonCommentHandling.Disallow;
        }

        o.MakeReadOnly(populateMissingResolver: true);
        return o;
    }

    public static string Id(Guid id) => id.ToString("N", CultureInfo.InvariantCulture);

    /// <summary>Parses an id from a path or query value; false for anything that is not a UUID.</summary>
    public static bool TryParseId(string? value, out Guid id)
    {
        id = default;
        return value is { Length: 32 or 36 } && Guid.TryParse(value, out id);
    }

    /// <summary>Reads and validates the JSON request body into <typeparamref name="T"/>, enforcing <paramref name="maxBytes"/> while streaming.</summary>
    public static async ValueTask<T> ReadBodyAsync<T>(HttpContext context, long maxBytes) where T : class =>
        (await ReadBodyCoreAsync<T>(context, maxBytes, null).ConfigureAwait(false));

    /// <summary>Like <see cref="ReadBodyAsync{T}"/> and also returns the SHA-256 digest of the exact request bytes as <c>sha256:&lt;hex&gt;</c> (idempotency fingerprint).</summary>
    public static async ValueTask<(T Value, string Digest)> ReadBodyWithDigestAsync<T>(HttpContext context, long maxBytes) where T : class
    {
        using var hash = System.Security.Cryptography.IncrementalHash.CreateHash(System.Security.Cryptography.HashAlgorithmName.SHA256);
        T value = await ReadBodyCoreAsync<T>(context, maxBytes, hash).ConfigureAwait(false);
        return (value, "sha256:" + Convert.ToHexStringLower(hash.GetHashAndReset()));
    }

    private static async ValueTask<T> ReadBodyCoreAsync<T>(HttpContext context, long maxBytes, System.Security.Cryptography.IncrementalHash? hash) where T : class
    {
        HttpRequest request = context.Request;
        if (request.ContentLength is { } declared && declared > maxBytes)
        {
            throw TooLarge(maxBytes);
        }

        if (request.ContentLength == 0)
        {
            throw ApiException.Validation("$", "A JSON object body is required.");
        }

        if (!System.Net.Http.Headers.MediaTypeHeaderValue.TryParse(request.ContentType, out var mediaType) || mediaType.MediaType is not { } type
            || !(type.Equals("application/json", StringComparison.OrdinalIgnoreCase) || type.EndsWith("+json", StringComparison.OrdinalIgnoreCase)))
        {
            throw new ApiException(StatusCodes.Status415UnsupportedMediaType, ApiCodes.UnsupportedMediaType, "The request body must be application/json.");
        }

        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit)
        {
            limit.MaxRequestBodySize = maxBytes;
        }

        try
        {
            await using var limited = new LimitedReadStream(request.Body, maxBytes, hash);
            T? value = await JsonSerializer.DeserializeAsync<T>(limited, Read, context.RequestAborted).ConfigureAwait(false);
            return value ?? throw ApiException.Validation("$", "A JSON object body is required.");
        }
        catch (JsonException ex)
        {
            throw ApiException.Validation(FieldOf(ex), MessageOf(ex));
        }
        catch (BadHttpRequestException ex) when (ex.StatusCode == StatusCodes.Status413PayloadTooLarge)
        {
            throw TooLarge(maxBytes);
        }
        catch (InvalidOperationException ex) when (ex.InnerException is JsonException inner)
        {
            throw ApiException.Validation(FieldOf(inner), MessageOf(inner));
        }
    }

    private static string FieldOf(JsonException ex)
    {
        string path = ex.Path ?? "$";
        return path.StartsWith("$.", StringComparison.Ordinal) ? path[2..] : path;
    }

    private static string MessageOf(JsonException ex) =>
        ex.Message.Contains("could not be mapped", StringComparison.Ordinal) || ex.Message.Contains("unmapped", StringComparison.OrdinalIgnoreCase)
            ? "Unknown member."
            : ex.InnerException is FormatException ? "Not valid base64."
            : "Missing, malformed or of the wrong type.";

    internal static ApiException TooLarge(long maxBytes) =>
        new(StatusCodes.Status413PayloadTooLarge, ApiCodes.PayloadTooLarge, $"The request body is larger than the allowed {maxBytes} bytes.");

    /// <summary>A stream that fails once more than <c>limit</c> bytes were read (bodies without a Content-Length are bounded too).</summary>
    private sealed class LimitedReadStream(Stream inner, long limit, System.Security.Cryptography.IncrementalHash? hash) : Stream
    {
        private long _read;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => _read;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException("Synchronous reads are not allowed.");

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int n = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            _read += n;
            hash?.AppendData(buffer.Span[..n]);
            if (_read > limit)
            {
                throw TooLarge(limit);
            }

            return n;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
