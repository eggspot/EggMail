using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace Mta.Storage.Model;

/// <summary>
/// Carries the provider's <see cref="IStorageModelHooks"/> inside <see cref="DbContextOptions"/>, so a context can be built from its
/// options alone. That is what EF's context pooling needs (<c>PooledDbContextFactory</c> constructs contexts with only the options),
/// and pooling is what keeps a hot read from paying for a fresh service scope each time.
/// </summary>
public sealed class ModelHooksOptionsExtension(IStorageModelHooks hooks) : IDbContextOptionsExtension
{
    public IStorageModelHooks Hooks { get; } = hooks;

    public DbContextOptionsExtensionInfo Info => new ExtensionInfo(this);

    public void ApplyServices(IServiceCollection services)
    {
    }

    public void Validate(IDbContextOptions options)
    {
    }

    private sealed class ExtensionInfo(ModelHooksOptionsExtension extension) : DbContextOptionsExtensionInfo(extension)
    {
        public override bool IsDatabaseProvider => false;

        public override string LogFragment => "using EggMail model hooks ";

        public override int GetServiceProviderHashCode() => 0;

        public override bool ShouldUseSameServiceProvider(DbContextOptionsExtensionInfo other) => other is ExtensionInfo;

        public override void PopulateDebugInfo(IDictionary<string, string> debugInfo) => debugInfo["EggMail:ModelHooks"] = ((ModelHooksOptionsExtension)Extension).Hooks.GetType().Name;
    }
}

public static class ModelHooksOptionsExtensions
{
    /// <summary>Attaches the hooks to the options (see <see cref="ModelHooksOptionsExtension"/>).</summary>
    public static DbContextOptionsBuilder<TContext> UseModelHooks<TContext>(this DbContextOptionsBuilder<TContext> builder, IStorageModelHooks hooks) where TContext : DbContext
    {
        ((IDbContextOptionsBuilderInfrastructure)builder).AddOrUpdateExtension(new ModelHooksOptionsExtension(hooks));
        return builder;
    }

    /// <summary>The hooks attached to <paramref name="options"/>, or the no-op hooks.</summary>
    public static IStorageModelHooks HooksOf(this DbContextOptions options) => options.FindExtension<ModelHooksOptionsExtension>()?.Hooks ?? NoModelHooks.Instance;
}
