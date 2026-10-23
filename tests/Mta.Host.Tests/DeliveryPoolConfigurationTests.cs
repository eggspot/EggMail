using Mta.Core;
using Mta.Host.Configuration;
using Mta.Host.Hosting;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Storage.Sqlite;

namespace Mta.Host.Tests;

public class DeliveryPoolConfigurationTests
{
    [Fact]
    public async Task The_runtime_pool_uses_the_configured_maximum_number_of_messages_per_connection()
    {
        string dir = Directory.CreateTempSubdirectory("eggmail-pool-config-").FullName;
        try
        {
            var config = new MtaConfig
            {
                Hostname = "egg.test",
                Storage = new StorageOptions { Sqlite = new SqliteOptions { DataDirectory = dir } },
                Smtp = new SmtpSection { Listeners = new Dictionary<string, ListenerSection> { ["submission"] = new() { Port = 0, BindAddress = "127.0.0.1", Mode = ListenerMode.StartTls, AuthRequired = true } } },
                Delivery = new DeliverySection { Throttle = new ThrottleSection { MaxMessagesPerConnection = 7 } },
            };
            SqliteStorage storage = SqliteStorage.Create(config.Storage);
            await storage.InitializeAsync(default);
            EggMailRuntime runtime = await EggMailRuntime.CreateAsync(config, storage, SystemClock.Instance, NullMtaLog.Instance, default);

            Assert.Equal(7, runtime.Pool.MaxMessagesPerConnection);

            await runtime.DisposeAsync();
            await storage.DisposeAsync();
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
