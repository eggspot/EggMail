namespace Mta.Observability;

public sealed record HealthWarning(string Code, string Message);

public sealed record HealthReport(bool Ready, IReadOnlyList<HealthWarning> Warnings, IReadOnlyDictionary<string, string> Details);

/// <summary>A component that contributes to readiness and to the persistent warning banner (decision P).</summary>
public interface IHealthContributor
{
    string Name { get; }

    ValueTask<HealthReport> CheckAsync(CancellationToken cancellationToken);
}

/// <summary>Aggregates contributors: ready only if every contributor is ready; warnings are concatenated.</summary>
public sealed class HealthService(IEnumerable<IHealthContributor> contributors)
{
    private readonly IHealthContributor[] _contributors = contributors.ToArray();

    public async ValueTask<HealthReport> CheckAsync(CancellationToken cancellationToken)
    {
        bool ready = true;
        var warnings = new List<HealthWarning>();
        var details = new Dictionary<string, string>();
        foreach (var c in _contributors)
        {
            HealthReport r;
            try
            {
                r = await c.CheckAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                r = new HealthReport(false, [new HealthWarning($"{c.Name}_check_failed", ex.Message)], new Dictionary<string, string>());
            }

            ready &= r.Ready;
            warnings.AddRange(r.Warnings);
            foreach (var (k, v) in r.Details)
            {
                details[$"{c.Name}.{k}"] = v;
            }
        }

        return new HealthReport(ready, warnings, details);
    }
}
