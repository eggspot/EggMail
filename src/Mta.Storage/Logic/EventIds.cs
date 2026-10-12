using System.Security.Cryptography;

namespace Mta.Storage.Logic;

/// <summary>
/// UUIDv7 generator for history events that is strictly increasing inside the process, even for several events in the
/// same millisecond (RFC 9562 method 1: a counter in the 12 "rand_a" bits). Event ids sort by their text form, so the
/// primary key order of <c>message_event</c> is the chronological order of the events of a message.
/// </summary>
public static class EventIds
{
    private static readonly object Gate = new();
    private static long s_lastMs = -1;
    private static int s_counter;

    public static Guid Next(DateTimeOffset at)
    {
        long ms = at.ToUnixTimeMilliseconds();
        int counter;
        lock (Gate)
        {
            if (ms <= s_lastMs)
            {
                ms = s_lastMs;
                counter = ++s_counter;
                if (counter > 0xFFF)
                {
                    ms++;
                    counter = 0;
                    s_counter = 0;
                }
            }
            else
            {
                counter = 0;
                s_counter = 0;
            }

            s_lastMs = ms;
        }

        Span<byte> b = stackalloc byte[16];
        b[0] = (byte)(ms >> 40);
        b[1] = (byte)(ms >> 32);
        b[2] = (byte)(ms >> 24);
        b[3] = (byte)(ms >> 16);
        b[4] = (byte)(ms >> 8);
        b[5] = (byte)ms;
        b[6] = (byte)(0x70 | ((counter >> 8) & 0x0F));
        b[7] = (byte)counter;
        RandomNumberGenerator.Fill(b[8..]);
        b[8] = (byte)((b[8] & 0x3F) | 0x80);
        return new Guid(b, bigEndian: true);
    }
}
