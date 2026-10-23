using System.Net;
using Mta.Host.Ingest;

namespace Mta.Host.Tests.Inbound;

public class InboundRateLimiterAtomicityTests
{
    [Fact]
    public void However_many_connections_ask_at_once_only_as_many_pass_as_the_limits_leave_room_for()
    {
        const int domainLimit = 10, perAddressLimit = 3, asksPerThreadFromEachSide = 8;
        var now = new DateTimeOffset(2026, 10, 16, 12, 0, 30, TimeSpan.Zero);
        for (int round = 0; round < 100; round++)
        {
            var limiter = new InboundRateLimiter();
            var domain = Guid.NewGuid();
            int passedFromOneAddress = 0, passedFromOthers = 0;
            using var gate = new ManualResetEventSlim();
            Thread[] threads = Enumerable.Range(0, 16).Select(t => new Thread(() =>
            {
                gate.Wait();
                for (int i = 0; i < asksPerThreadFromEachSide; i++)
                {
                    if (limiter.TryCount(domain, IPAddress.Parse("203.0.113.9"), domainLimit, perAddressLimit, now))
                    {
                        Interlocked.Increment(ref passedFromOneAddress);
                    }

                    if (limiter.TryCount(domain, IPAddress.Parse($"198.51.{t}.{i + 1}"), domainLimit, perAddressLimit, now))
                    {
                        Interlocked.Increment(ref passedFromOthers);
                    }
                }
            })).ToArray();
            foreach (Thread thread in threads)
            {
                thread.Start();
            }

            gate.Set();
            foreach (Thread thread in threads)
            {
                thread.Join();
            }

            Assert.True(passedFromOneAddress <= perAddressLimit, $"round {round}: {passedFromOneAddress} passed a per-address limit of {perAddressLimit}");
            Assert.True(passedFromOneAddress + passedFromOthers <= domainLimit, $"round {round}: {passedFromOneAddress + passedFromOthers} passed a domain limit of {domainLimit}");
            Assert.Equal(domainLimit, passedFromOneAddress + passedFromOthers);
        }
    }

    [Fact]
    public void A_refused_ask_counts_nothing()
    {
        var now = new DateTimeOffset(2026, 10, 16, 12, 0, 30, TimeSpan.Zero);
        var limiter = new InboundRateLimiter();
        var domain = Guid.NewGuid();
        var client = IPAddress.Parse("203.0.113.9");

        Assert.True(limiter.TryCount(domain, client, 5, 1, now));
        for (int i = 0; i < 20; i++)
        {
            Assert.False(limiter.TryCount(domain, client, 5, 1, now));
        }

        Assert.True(limiter.TryCount(domain, IPAddress.Parse("203.0.113.10"), 5, 1, now));
        Assert.True(limiter.TryCount(domain, IPAddress.Parse("203.0.113.11"), 5, 1, now));
        Assert.True(limiter.TryCount(domain, IPAddress.Parse("203.0.113.12"), 5, 1, now));
        Assert.True(limiter.TryCount(domain, IPAddress.Parse("203.0.113.13"), 5, 1, now));
        Assert.False(limiter.TryCount(domain, IPAddress.Parse("203.0.113.14"), 5, 1, now));
    }
}
