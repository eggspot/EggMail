using Mta.Core;

namespace Mta.Dns.Tests;

internal sealed class FakeClock : IClock
{
    private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public DateTimeOffset UtcNow => _now;

    public long Timestamp => _now.Ticks;

    public void Advance(TimeSpan by) => _now += by;
}
