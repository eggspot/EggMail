using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Mta.Authentication.Tests;

/// <summary>
/// RFC 6376 written again from the RFC text with plain strings and the BCL only, sharing no code with <c>Mta.Dkim</c> and nothing with MimeKit. It exists to be a third
/// opinion: if the signer, this and MimeKit all agree about a signature, a mistake in the shared understanding of the RFC is the only thing left that could be wrong.
/// </summary>
internal static class IndependentDkim
{
    public sealed record Field(string Raw, string Name);

    public static (List<Field> Fields, string Body) Split(string message)
    {
        int split = message.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        string head = split < 0 ? message : message[..(split + 2)];
        string body = split < 0 ? string.Empty : message[(split + 4)..];
        var fields = new List<Field>();
        var current = new StringBuilder();
        foreach (string line in head.Split("\r\n").SkipLast(1))
        {
            if (line.Length > 0 && (line[0] == ' ' || line[0] == '\t'))
            {
                current.Append(line).Append("\r\n");
                continue;
            }

            if (current.Length > 0)
            {
                fields.Add(ToField(current.ToString()));
                current.Clear();
            }

            current.Append(line).Append("\r\n");
        }

        if (current.Length > 0)
        {
            fields.Add(ToField(current.ToString()));
        }

        return (fields, body);
    }

    private static Field ToField(string raw) => new(raw, raw[..raw.IndexOf(':')].Trim(' ', '\t').ToLowerInvariant());

    public static string CanonHeader(string raw, bool relaxed)
    {
        if (!relaxed)
        {
            return raw;
        }

        int colon = raw.IndexOf(':');
        string name = raw[..colon].Trim(' ', '\t').ToLowerInvariant();
        string value = raw[(colon + 1)..].Replace("\r\n", string.Empty);
        value = Regex.Replace(value, "[ \t]+", " ").Trim(' ');
        return name + ":" + value + "\r\n";
    }

    public static string CanonBody(string body, bool relaxed)
    {
        var lines = body.Split("\r\n").ToList();
        if (lines.Count > 0 && lines[^1].Length == 0)
        {
            lines.RemoveAt(lines.Count - 1);
        }
        else if (lines.Count > 0 && body.Length > 0)
        {
            // a body that does not end in CRLF gets one
        }

        if (relaxed)
        {
            lines = lines.Select(l => Regex.Replace(l, "[ \t]+", " ").TrimEnd(' ')).ToList();
        }

        while (lines.Count > 0 && lines[^1].Length == 0)
        {
            lines.RemoveAt(lines.Count - 1);
        }

        return lines.Count == 0 ? (relaxed ? string.Empty : "\r\n") : string.Concat(lines.Select(l => l + "\r\n"));
    }

    public static Dictionary<string, string> Tags(string signatureField)
    {
        string value = signatureField[(signatureField.IndexOf(':') + 1)..].Replace("\r\n", string.Empty);
        var tags = new Dictionary<string, string>();
        foreach (string part in value.Split(';'))
        {
            int eq = part.IndexOf('=');
            if (eq > 0)
            {
                string name = part[..eq].Trim();
                string tagValue = part[(eq + 1)..].Trim();
                tags[name] = name is "b" or "bh" ? Regex.Replace(tagValue, @"\s+", string.Empty) : tagValue;   // folding white space is not part of a base64 value
            }
        }

        return tags;
    }

    /// <summary>The data a verifier hashes: the selected headers, bottom-up per name, then the signature field with an empty b= and without its final CRLF (RFC 6376 section 3.7).</summary>
    public static byte[] SigningInput(string message, string signatureField, bool? headerRelaxedOverride = null)
    {
        var tags = Tags(signatureField);
        bool relaxed = headerRelaxedOverride ?? tags.GetValueOrDefault("c", "simple/simple").Split('/')[0] == "relaxed";
        var (fields, _) = Split(message);
        var used = new HashSet<Field>();
        var input = new StringBuilder();
        foreach (string name in tags["h"].Split(':').Select(n => n.Trim().ToLowerInvariant()))
        {
            for (int i = fields.Count - 1; i >= 0; i--)
            {
                if (fields[i].Name == name && !used.Contains(fields[i]) && fields[i].Raw != signatureField)
                {
                    used.Add(fields[i]);
                    input.Append(CanonHeader(fields[i].Raw, relaxed));
                    break;
                }
            }
        }

        input.Append(CanonHeader(EmptyB(signatureField), relaxed).TrimEnd('\r', '\n'));
        return Encoding.Latin1.GetBytes(input.ToString());
    }

    private static string EmptyB(string signatureField)
    {
        int colon = signatureField.IndexOf(':');
        string[] parts = signatureField[(colon + 1)..].Split(';');
        for (int i = 0; i < parts.Length; i++)
        {
            int eq = parts[i].IndexOf('=');
            if (eq > 0 && parts[i][..eq].Trim() == "b")
            {
                parts[i] = parts[i][..(eq + 1)];
            }
        }

        return signatureField[..(colon + 1)] + string.Join(';', parts);
    }

    public static string BodyHash(string message, Dictionary<string, string> tags)
    {
        bool relaxed = tags.GetValueOrDefault("c", "simple/simple").Split('/') is { Length: 2 } c && c[1] == "relaxed";
        byte[] body = Encoding.Latin1.GetBytes(CanonBody(Split(message).Body, relaxed));
        if (tags.TryGetValue("l", out string? l) && long.TryParse(l, out long limit) && limit < body.Length)
        {
            body = body[..(int)limit];
        }

        return Convert.ToBase64String(SHA256.HashData(body));
    }

    /// <summary>Verifies every DKIM-Signature of the message against <paramref name="publicKey"/>; returns one verdict per signature, in message order.</summary>
    public static List<bool> Verify(string message, RSA publicKey)
    {
        var results = new List<bool>();
        foreach (var field in Split(message).Fields.Where(f => f.Name == "dkim-signature"))
        {
            var tags = Tags(field.Raw);
            bool bodyOk = tags["bh"].Replace(" ", string.Empty) == BodyHash(message, tags);
            byte[] signature = Convert.FromBase64String(Regex.Replace(tags["b"], @"\s+", string.Empty));
            bool signatureOk = publicKey.VerifyData(SigningInput(message, field.Raw), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            results.Add(bodyOk && signatureOk);
        }

        return results;
    }

    /// <summary>
    /// Signs the same input with the private key and returns the base64 that b= must hold. RSASSA-PKCS1-v1_5 is deterministic, so a correct signer produces exactly this.
    /// </summary>
    public static string ExpectedB(string message, string signatureField, RSA privateKey) =>
        Convert.ToBase64String(privateKey.SignData(SigningInput(message, signatureField), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
}

/// <summary>The <c>openssl</c> command line as a fourth opinion: it verifies the RSA signature over the signing input, nothing of DKIM is implemented by it.</summary>
internal static class OpenSsl
{
    private static readonly Lazy<string?> Path = new(Find);

    public static bool Available => Path.Value is not null;

    private static string? Find()
    {
        foreach (string candidate in new[] { "/usr/bin/openssl", "/usr/local/bin/openssl", "/opt/homebrew/bin/openssl", "/bin/openssl" })
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    /// <summary><c>openssl dgst -sha256 -verify pub.pem -signature sig.bin data.bin</c>.</summary>
    public static bool Verify(byte[] data, byte[] signature, RSA publicKey)
    {
        string dir = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "egg-openssl-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(System.IO.Path.Combine(dir, "pub.pem"), publicKey.ExportSubjectPublicKeyInfoPem());
            File.WriteAllBytes(System.IO.Path.Combine(dir, "data.bin"), data);
            File.WriteAllBytes(System.IO.Path.Combine(dir, "sig.bin"), signature);
            var start = new ProcessStartInfo(Path.Value!, ["dgst", "-sha256", "-verify", "pub.pem", "-signature", "sig.bin", "data.bin"])
            {
                WorkingDirectory = dir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using var process = Process.Start(start)!;
            process.StandardOutput.ReadToEnd();
            process.StandardError.ReadToEnd();
            process.WaitForExit();
            return process.ExitCode == 0;
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

/// <summary>A fact that is reported as skipped where there is no <c>openssl</c> binary.</summary>
public sealed class OpenSslFactAttribute : FactAttribute
{
    public override string Skip
    {
        get => base.Skip ?? (OpenSsl.Available ? null! : "no openssl command line tool on this machine");
        set => base.Skip = value;
    }
}

/// <summary>A theory that is reported as skipped where there is no <c>openssl</c> binary.</summary>
public sealed class OpenSslTheoryAttribute : TheoryAttribute
{
    public override string Skip
    {
        get => base.Skip ?? (OpenSsl.Available ? null! : "no openssl command line tool on this machine");
        set => base.Skip = value;
    }
}
