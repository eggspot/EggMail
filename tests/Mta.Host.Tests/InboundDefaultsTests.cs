using Mta.Host.Api;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Tests;

/// <summary>
/// The inbound defaults live in three places by necessity (the storage options the retention job reads, the configuration section the receive path reads and the defaults the settings
/// API reports); this pins them equal, so the API never reports a value the server does not apply.
/// </summary>
public class InboundDefaultsTests
{
    [Fact]
    public void The_storage_options_the_configuration_section_and_the_api_defaults_agree()
    {
        var config = new MtaConfig();
        InboundApiDefaults api = new();
        InboundApiDefaults fromConfig = EggMailApiExtensions.InboundDefaultsFrom(config);

        Assert.Equal(api.MaxMessagesPerMinute, config.Inbound.MaxMessagesPerMinute);
        Assert.Equal(api.MaxMessagesPerMinutePerRemote, config.Inbound.MaxMessagesPerMinutePerRemote);
        Assert.Equal(api.MaxStoredBytesPerDomain, config.Inbound.MaxStoredBytesPerDomain);
        Assert.Equal(api.MaxStoredBytesPerTenant, config.Inbound.MaxStoredBytesPerTenant);
        Assert.Equal(api.RetentionDays, new InboundStorageOptions().RetentionDays);
        Assert.Equal(api.MaxRetentionDays, new InboundStorageOptions().MaxRetentionDays);

        // What the API reports for a server nobody configured is what the API alone would say, except the message size, which follows Smtp:MaxMessageSize.
        Assert.Equal(config.Smtp.MaxMessageSize, fromConfig.MaxMessageBytes);
        Assert.Equal(api.Ceilings() with { MaxMessageBytes = fromConfig.MaxMessageBytes }, fromConfig.Ceilings());
        Assert.Equal(api.RetentionDays, fromConfig.RetentionDays);
    }
}
