using Mta.Core;

namespace Mta.Storage.Logic;

/// <summary>Text form of mailboxes as stored in queue and history columns.</summary>
public static class AddressText
{
    /// <summary><c>local@domain</c>, or the empty string for the null reverse-path.</summary>
    public static string Format(EmailAddress address) => address.IsNull ? "" : address.LocalPart + "@" + address.Domain;

    /// <summary>Inverse of <see cref="Format"/>; the empty string is the null reverse-path.</summary>
    public static EmailAddress Parse(string text)
    {
        if (text.Length == 0)
        {
            return EmailAddress.Null;
        }

        return EmailAddress.TryParse(text, allowUtf8: true, out var address)
            ? address
            : throw new InvalidDataException($"Stored mailbox is not valid: {text}");
    }
}
