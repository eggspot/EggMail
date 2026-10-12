using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Mta.Core;

namespace Mta.Storage.Postgres;

public static class PostgresStorageServiceCollectionExtensions
{
    /// <summary>
    /// Registers the PostgreSQL backend as a singleton <see cref="IStorage"/> (and its parts). Uses a registered
    /// <see cref="IClock"/> and <see cref="IMtaLog"/> when present. The host must call
    /// <c>IStorage.InitializeAsync</c> once at startup before serving traffic.
    /// </summary>
    public static IServiceCollection AddEggMailPostgresStorage(this IServiceCollection services, StorageOptions options)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(options);
        services.TryAddSingleton(options);
        services.TryAddSingleton<PostgresStorage>(sp => PostgresStorage.Create(options, sp.GetService<IClock>(), sp.GetService<IMtaLog>()));
        services.TryAddSingleton<IStorage>(sp => sp.GetRequiredService<PostgresStorage>());
        services.TryAddSingleton(sp => sp.GetRequiredService<IStorage>().Intake);
        services.TryAddSingleton(sp => sp.GetRequiredService<IStorage>().Deliveries);
        services.TryAddSingleton(sp => sp.GetRequiredService<IStorage>().Config);
        services.TryAddSingleton(sp => sp.GetRequiredService<IStorage>().Stats);
        services.TryAddSingleton(sp => sp.GetRequiredService<IStorage>().History);
        services.TryAddSingleton(sp => sp.GetRequiredService<IStorage>().Webhooks);
        services.TryAddSingleton(sp => sp.GetRequiredService<IStorage>().Maintenance);
        return services;
    }
}
