using System.Collections.Concurrent;

namespace Mta.Core;

/// <summary>
/// The lower-case ASCII host names seen in addresses, kept so that the next message from or to the same domain does not allocate its
/// name again. A bounded table: once it is full, new names are simply allocated as before (nothing is evicted, so a flood of distinct
/// names costs the later, legitimate names an allocation and nothing else). The strings are immutable and shared, so no caller can
/// observe the table.
/// </summary>
internal static class DomainNames
{
    private const int MaxEntries = 2048;
    private const int MaxLength = 100;

    private static readonly ConcurrentDictionary<string, string> Table = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, string>.AlternateLookup<ReadOnlySpan<char>> Lookup = Table.GetAlternateLookup<ReadOnlySpan<char>>();
    private static int _count;

    /// <summary>The lower-case form of <paramref name="name"/>, which must be a validated ASCII host name without a trailing dot.</summary>
    public static string Intern(ReadOnlySpan<char> name)
    {
        if (Lookup.TryGetValue(name, out string? known))
        {
            return known;
        }

        string lower = string.Create(name.Length, name, static (destination, source) =>
        {
            for (int i = 0; i < source.Length; i++)
            {
                char c = source[i];
                destination[i] = c is >= 'A' and <= 'Z' ? (char)(c + 32) : c;
            }
        });

        if (name.Length <= MaxLength && Volatile.Read(ref _count) < MaxEntries && Table.TryAdd(lower, lower))
        {
            Interlocked.Increment(ref _count);
        }

        return lower;
    }
}

/// <summary>
/// A small memo of the mailboxes one connection parsed recently (the sender of every message of a session, a recipient that comes back).
/// <see cref="TryParse"/> gives exactly the result of <see cref="EmailAddress.TryParse(ReadOnlySpan{char}, bool, out EmailAddress)"/>; a hit only avoids
/// allocating the two strings again. Not thread safe: one instance belongs to one session, which parses one command at a time.
/// </summary>
public sealed class EmailAddressCache
{
    private const int Slots = 4;

    private readonly EmailAddress[] _addresses = new EmailAddress[Slots];
    private readonly bool[] _allowUtf8 = new bool[Slots];
    private int _used;
    private int _next;

    public bool TryParse(ReadOnlySpan<char> mailbox, bool allowUtf8, out EmailAddress address)
    {
        for (int i = 0; i < _used; i++)
        {
            if (_allowUtf8[i] == allowUtf8 && IsSameText(_addresses[i], mailbox))
            {
                address = _addresses[i];
                return true;
            }
        }

        if (!EmailAddress.TryParse(mailbox, allowUtf8, out address))
        {
            return false;
        }

        // Only an address whose text is exactly local@domain is remembered (it is compared against its own parts, so no key string is kept).
        if (IsSameText(address, mailbox))
        {
            _addresses[_next] = address;
            _allowUtf8[_next] = allowUtf8;
            _next = (_next + 1) % Slots;
            _used = Math.Min(Slots, _used + 1);
        }

        return true;
    }

    private static bool IsSameText(in EmailAddress address, ReadOnlySpan<char> mailbox)
    {
        string local = address.LocalPart;
        string domain = address.Domain;
        return mailbox.Length == local.Length + 1 + domain.Length
            && mailbox[local.Length] == '@'
            && mailbox[..local.Length].SequenceEqual(local)
            && mailbox[(local.Length + 1)..].SequenceEqual(domain);
    }
}
