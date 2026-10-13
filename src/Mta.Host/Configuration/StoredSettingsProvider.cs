using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Memory;

namespace Mta.Host.Configuration;

/// <summary>
/// The configuration layer made of the global settings kept in the config store (decision N, layer 4). It is a distinct provider type so
/// code that asks "which layer supplies this key" (the backend switch, which must not treat a stored value as a deployment lock) can tell
/// it apart from the deployment layers.
/// </summary>
public sealed class StoredSettingsConfigurationSource(IEnumerable<KeyValuePair<string, string?>> values) : IConfigurationSource
{
    public IConfigurationProvider Build(IConfigurationBuilder builder) => new StoredSettingsProvider(new MemoryConfigurationSource { InitialData = values });
}

/// <summary>Provider of <see cref="StoredSettingsConfigurationSource"/>.</summary>
public sealed class StoredSettingsProvider(MemoryConfigurationSource source) : MemoryConfigurationProvider(source);
