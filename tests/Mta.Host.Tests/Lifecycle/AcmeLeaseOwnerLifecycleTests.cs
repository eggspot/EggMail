using System.Reflection;
using Mta.Host.Configuration;
using Mta.Host.Tls;
using Mta.TestSupport;

namespace Mta.Host.Tests.Lifecycle;

public class AcmeLeaseOwnerLifecycleTests
{
    private sealed class NullRunner : IAcmeOrderRunner
    {
        public Task<AcmeIssuedCertificate> IssueAsync(AcmeOrderRequest request, IDnsChallengeProvider dns, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    /// <summary>
    /// Regression: the owner name of a renewal service was the first 12 hex digits of a UUIDv7, which is the millisecond timestamp. Replicas created in the same
    /// millisecond got the same name, and the renewal lease (which treats the same owner as a re-entry) let both of them order.
    /// </summary>
    [Fact]
    public void Lifecycle_renewal_services_created_together_never_share_a_lease_owner()
    {
        FieldInfo owner = typeof(AcmeRenewalService).GetField("_owner", BindingFlags.Instance | BindingFlags.NonPublic)!;
        var names = new HashSet<string>();
        for (int i = 0; i < 2000; i++)
        {
            var service = new AcmeRenewalService(null!, null!, new NullRunner(), null, new AcmeSection(), new VirtualClock());
            Assert.True(names.Add((string)owner.GetValue(service)!), $"owner name collision at service {i}");
        }
    }
}
