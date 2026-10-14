namespace Mta.Core;

/// <summary>
/// Protects secrets at rest (DKIM private keys, webhook secrets, ACME and TLS keys, relay passwords). The host implements it
/// with ASP.NET Core Data Protection (decision H); purposes separate the key domains.
/// </summary>
public interface ISecretProtector
{
    byte[] Protect(ReadOnlySpan<byte> plaintext, string purpose);

    byte[] Unprotect(ReadOnlySpan<byte> protectedData, string purpose);
}

/// <summary>Well-known purpose strings for <see cref="ISecretProtector"/>.</summary>
public static class SecretPurposes
{
    public const string DkimKey = "EggMail.Secrets.DkimKey.v1";
    public const string WebhookSecret = "EggMail.Secrets.WebhookSecret.v1";
    public const string TlsPrivateKey = "EggMail.Secrets.TlsPrivateKey.v1";
    public const string AcmeAccountKey = "EggMail.Secrets.AcmeAccountKey.v1";
    public const string RelayPassword = "EggMail.Secrets.RelayPassword.v1";
    public const string AuthThrottleKey = "EggMail.Secrets.AuthThrottleKey.v1";
}
