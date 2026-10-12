namespace Mta.Policy;

/// <summary>
/// A ramp-up table of daily sending caps indexed by days since a sending domain started sending (day 0 is the first day).
/// After the last table entry the domain has graduated and no warm-up cap applies (unless a final cap is given).
/// </summary>
public sealed class WarmupSchedule
{
    private readonly long[] _caps;

    /// <summary>
    /// The proposed default ramp: 50, 100, 200, 400, 800, 1,500, 3,000, 5,000, 10,000, 20,000, 40,000 messages per day, then no warm-up cap.
    /// These numbers are a design-author proposal, not an ISP standard; tune them to your IP reputation and provider guidance.
    /// </summary>
    public static WarmupSchedule Default { get; } = new([50, 100, 200, 400, 800, 1_500, 3_000, 5_000, 10_000, 20_000, 40_000]);

    /// <summary>Creates a schedule from daily caps (positive, non-decreasing).</summary>
    /// <param name="dailyCaps">Cap for day 0, day 1, ...</param>
    /// <param name="capAfterSchedule">Cap that applies once the table is exhausted; null means no warm-up cap (graduated).</param>
    public WarmupSchedule(IEnumerable<long> dailyCaps, long? capAfterSchedule = null)
    {
        ArgumentNullException.ThrowIfNull(dailyCaps);
        _caps = [.. dailyCaps];
        if (_caps.Length == 0)
        {
            throw new ArgumentException("A warm-up schedule needs at least one day.", nameof(dailyCaps));
        }

        long previous = 0;
        foreach (long cap in _caps)
        {
            if (cap <= 0 || cap < previous)
            {
                throw new ArgumentException("Warm-up caps must be positive and non-decreasing.", nameof(dailyCaps));
            }

            previous = cap;
        }

        if (capAfterSchedule is { } after && after < previous)
        {
            throw new ArgumentOutOfRangeException(nameof(capAfterSchedule), "The final cap must not be below the last scheduled day.");
        }

        CapAfterSchedule = capAfterSchedule;
    }

    /// <summary>The configured daily caps.</summary>
    public IReadOnlyList<long> DailyCaps => _caps;

    /// <summary>The cap after the table ends, or null for "graduated".</summary>
    public long? CapAfterSchedule { get; }

    /// <summary>The cap for a zero-based day number. Negative days count as day 0. Returns null once warm-up is over.</summary>
    public long? GetDailyCap(int dayIndex)
    {
        if (dayIndex < 0)
        {
            dayIndex = 0;
        }

        return dayIndex < _caps.Length ? _caps[dayIndex] : CapAfterSchedule;
    }

    /// <summary>The cap for <paramref name="today"/> given the UTC day sending started.</summary>
    public long? GetDailyCap(DateOnly startDay, DateOnly today) => GetDailyCap(today.DayNumber - startDay.DayNumber);

    /// <summary>True once the table is exhausted and no cap (or only the final cap) applies.</summary>
    public bool IsGraduated(int dayIndex) => dayIndex >= _caps.Length;
}
