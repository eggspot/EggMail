namespace Mta.Host.Configuration;

/// <summary>Checks the process makes before it accepts traffic.</summary>
public sealed class StartupSection
{
    /// <summary>
    /// Refuse to start when the Unicode self-test fails (typically <c>DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1</c> or no ICU library: internationalized domain
    /// names and normalization would be wrong without any error). <c>false</c> only logs a warning.
    /// </summary>
    public bool RequireUnicodeSupport { get; init; } = true;
}
