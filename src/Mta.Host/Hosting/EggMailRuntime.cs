using Mta.Core;
using Mta.Delivery;
using Mta.Dkim;
using Mta.Dns;
using Mta.Dsn;
using Mta.Host.Configuration;
using Mta.Host.Ingest;
using Mta.Host.Security;
using Mta.Host.Submission;
using Mta.Host.Tls;
using Mta.Observability;
using Mta.Policy;
using Mta.Smtp.Client;
using Mta.Smtp.Server;
using Mta.Storage;
using Mta.Tls;
using Mta.Tls.MtaSts;
using Mta.Tls.Dane;
using Mta.Tls.TlsRpt;
using Mta.Host.Reports;
using Mta.Webhooks;

namespace Mta.Host.Hosting;

/// <summary>
/// Everything the process runs, wired from configuration and an initialized storage: the SMTP server with its handler, the delivery
/// engine, the webhook dispatcher and the certificate provider. Built once at startup; the hosted services only start and stop the parts.
/// </summary>
public sealed class EggMailRuntime : IAsyncDisposable
{
    public required MtaConfig Config { get; init; }
    public required IStorage Storage { get; init; }
    public required IClock Clock { get; init; }
    public required IMtaLog Log { get; init; }
    public required ISecretProtector Secrets { get; init; }
    public required DatabaseCertificateProvider Certificates { get; init; }
    public required VerpCodec Verp { get; init; }
    public required SubmissionService Submission { get; init; }
    public required AuthThrottle AuthThrottle { get; init; }
    public required SmtpServer SmtpServer { get; init; }
    public required DeliveryEngine Delivery { get; init; }
    public required WebhookDispatcher Webhooks { get; init; }
    public required IDnsResolver Dns { get; init; }
    public required SmtpConnectionPool Pool { get; init; }
    public required RoutePlanner Routes { get; init; }
    public required SendingLimits Limits { get; init; }
    /// <summary>Whether every key at rest is protected (not only: the mode is not <c>None</c>); what the backend switch tells a target about this instance.</summary>
    public bool KeysProtectedAtRest { get; init; }

    public AcmeRenewalService? Acme { get; init; }

    /// <summary>The MX receiver of inbound mail (null unless <c>Inbound:Enabled</c>).</summary>
    public InboundReceiver? Inbound { get; init; }

    /// <summary>The receive path's copy of the enabled domains and routes (null unless <c>Inbound:Enabled</c>); the API asks it to reload after it changes something (<see cref="InboundConfigurationCache.RequestRefresh"/>).</summary>
    public InboundConfigurationCache? InboundConfiguration { get; init; }

    /// <summary>The built-in HTTP-01 responder (null unless ACME is on and answers HTTP-01 challenges itself, <c>Acme:Challenge</c>); it runs on every replica.</summary>
    public AcmeHttpChallengeListener? AcmeHttpListener { get; init; }

    /// <summary>The circuit breakers per route and MX host (shared among replicas through <see cref="ReplicaCoordinator"/>).</summary>
    public required RouteHealth Health { get; init; }

    /// <summary>The per-destination connection and rate limits of the delivery engine (shared among replicas through <see cref="ReplicaCoordinator"/>).</summary>
    public required DestinationThrottle DestinationThrottle { get; init; }

    /// <summary>Coordinates with the other replicas on the same database (live set, shares of the destination ceilings, learned back-off and open circuits); null when the storage has no replica coordination (SQLite).</summary>
    public ReplicaCoordinator? ReplicaCoordinator { get; init; }
    public TlsReportSender? TlsReports { get; init; }

    /// <summary>Persists the sending counters (write-behind); loaded before the first delivery, flushed by <see cref="FlushRuntimeStateAsync"/>.</summary>
    public required SendingCounterPersistence CounterPersistence { get; init; }

    /// <summary>Persists the TLS-RPT counters; null when TLS reporting is off.</summary>
    public TlsReportJournal? TlsJournal { get; init; }

    /// <summary>The in-memory TLS-RPT counters the delivery engine records into; null when TLS reporting is off.</summary>
    public TlsRptCollector? TlsCollector { get; init; }

    private readonly List<IAsyncDisposable> _owned = [];

    public static async Task<EggMailRuntime> CreateAsync(MtaConfig config, IStorage storage, IClock clock, IMtaLog log, CancellationToken ct, IDnsResolver? dnsOverride = null,
        IAcmeOrderRunner? acmeRunnerOverride = null, IDnsChallengeProvider? acmeDnsOverride = null, bool hostnameConfigured = true)
    {
        var secrets = Mta.Host.Secrets.SecretsFactory.Create(config.Secrets, storage.Config);
        foreach (string warning in Mta.Host.Secrets.SecretsFactory.Warnings(config.Secrets, storage.Config))
        {
            log.Write(MtaLogLevel.Warning, "startup", warning);
        }

        if (config.Secrets.KeyProtection == KeyProtectionMode.None)
        {
            log.Write(MtaLogLevel.Warning, "startup", "Secrets:KeyProtection is None: the Data Protection key ring is stored unprotected. Use a certificate in production.");
        }

        var certificates = new DatabaseCertificateProvider(storage.Config, secrets, config.Hostname, config.Tls, clock, log, replaceOnHostnameChange: hostnameConfigured);
        await certificates.InitializeAsync(ct).ConfigureAwait(false);
        var certificateMeters = Mta.Host.Tls.TlsMetrics.Attach(certificates, clock);
        System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(typeof(ProcessMetrics).TypeHandle);   // publishes the Mta.Process gauges (descriptors, threads) to the exporters
        var verp = await VerpKeyStore.LoadOrCreateAsync(storage.Config, ct).ConfigureAwait(false);

        var dns = dnsOverride ?? CreateDns(config);
        var storageOptions = config.Storage;
        var submission = new SubmissionService(
            storage, clock, new SenderPolicy(), storageOptions,
            new SubmissionOptions { MessageIdDomain = config.Hostname, MaxMessageBytes = config.Smtp.MaxMessageSize, MaxRecipients = config.Smtp.MaxRecipients });
        // Several replicas on one database count failed logins together; SQLite (one process) and a store without coordination count in memory, which is exact there.
        IReplicaCoordination? sharedFailures = storage.Replicas;
        byte[]? digestKey = null;
        if (sharedFailures is not null)
        {
            try
            {
                digestKey = await AuthThrottleKeyStore.LoadOrCreateAsync(storage.Config, secrets, clock, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log.Write(MtaLogLevel.Warning, "auth", "could not read or create the failed-login digest key", ex);
            }

            if (digestKey is null)
            {
                log.Write(MtaLogLevel.Warning, "auth", "failed logins are counted per process until the failed-login digest key can be stored");
                sharedFailures = null;
            }
        }

        var throttle = new AuthThrottle(clock, shared: sharedFailures, digestKey: digestKey, log: log);

        var bounces = new BounceProcessor(verp, storage.Config, storage.Stats, new StorageWebhookPublisher(storage), clock, log, history: storage.History);
        DeliveryEngine? engine = null;
        var handler = new IngestHandler(storage, submission, throttle, new IngestOptions { BounceDomain = config.Delivery.BounceDomain, MaxRecipientsPerMessage = config.Smtp.MaxRecipients }, bounces, onAccepted: () => engine?.Wake(), log);

        // Inbound mail: the port-25 listener becomes an MX receiver. Everything is built only when Inbound:Enabled; off, the server behaves exactly as before.
        InboundReceiveOptions inboundOptions = InboundReceiveOptions.From(config);
        InboundReceiver? inbound = null;
        InboundConfigurationCache? inboundConfiguration = null;
        if (inboundOptions.Enabled)
        {
            inboundConfiguration = new InboundConfigurationCache(storage.Inbound, clock, inboundOptions, log);
            var srs = new SrsCodec(verp, inboundOptions.SrsMaxAgeDays);
            inbound = new InboundReceiver(
                handler, storage.Inbound, inboundConfiguration, new InboundVerifier(dns, inboundOptions, config.Hostname, clock),
                new VerificationSlots(inboundOptions.VerificationMaxConcurrency, inboundOptions.VerificationMaxConcurrencyPerRemote), new InboundRateLimiter(),
                new DnsblChecker(dns, inboundOptions.DnsblZones, inboundOptions.DnsblTimeout), srs, new ForwardHopMarker(verp), inboundOptions, config.Hostname, clock, log, onAccepted: () => engine?.Wake());
            handler.UseInbound(inbound);
        }

        var listeners = config.Smtp.Listeners.Where(l => l.Value.Enabled).Select(l => InboundListener(l.Value.ToOptions(l.Key), inboundOptions)).ToList();
        var smtp = new SmtpServer(new SmtpServerOptions
        {
            Hostname = config.Hostname,
            Certificates = certificates,
            MaxMessageSize = config.Smtp.MaxMessageSize,
            MaxRecipients = config.Smtp.MaxRecipients,
            MaxConnections = config.Smtp.MaxConnections,
            MaxConnectionsPerIp = config.Smtp.MaxConnectionsPerIp,
            MaxInFlightBytes = config.Smtp.MaxInFlightBytes,
            Chunking = config.Smtp.Chunking,
            SmtpUtf8 = config.Smtp.SmtpUtf8,
            Listeners = listeners,
        }, handler, clock, log);

        // Outbound stack.
        var deliveryOptions = new DeliveryOptions
        {
            Hostname = config.Hostname,
            MaxConcurrentGroups = config.Delivery.Workers,
            ClaimBatchSize = config.Delivery.ClaimBatchSize,
            Lease = config.Delivery.ClaimLease,
            IdlePoll = config.Delivery.PollInterval,
            MaxRecipientsPerTransaction = config.Delivery.MaxRecipientsPerTransaction,
            BounceDomain = config.Delivery.BounceDomain,
            RemotePort = config.Delivery.RemotePort,
            PublicSendingIp = config.Delivery.PublicSendingIp,
        };
        var collector = config.Tls.ReportingEnabled ? new TlsRptCollector(clock) : null;
        var mx = new MxResolver(dns, new MxResolverOptions { ExcludeSpecialAddresses = !config.Delivery.AllowPrivateMxAddresses });
        var mtaSts = new MtaStsPolicyStore(dns, new MtaStsPolicyFetcher(), clock: clock);
        var tls = new OutboundTlsPolicyResolver(mtaSts, new DaneTlsaLookup(dns));
        var pool = new SmtpConnectionPool(new SmtpClientOptions { HeloName = config.Delivery.HeloName ?? config.Hostname, PreferChunking = config.Delivery.PreferChunking }, clock, maxIdlePerTarget: config.Delivery.MaxIdleConnectionsPerTarget);
        var routeHealth = new RouteHealth(clock);
        var routes = new RoutePlanner(routeHealth);
        var sendingCounters = new InMemorySendingCounterStore();
        var limits = new SendingLimits(clock, sendingCounters, SendingConfigurator.OptionsFrom(config.Sending));
        // The current hour and day windows as they were before a restart: the caps and the warm-up must not start from zero again.
        var counterPersistence = new SendingCounterPersistence(sendingCounters, storage.Config, clock);
        await counterPersistence.LoadAsync(ct).ConfigureAwait(false);
        var destinationThrottle = new DestinationThrottle(clock, new DestinationThrottleOptions
        {
            Defaults = new ThrottleLimits(config.Delivery.Throttle.MaxConnections, config.Delivery.Throttle.MaxMessagesPerMinute, config.Delivery.Throttle.MaxMessagesPerConnection),
            InitialConcurrentConnections = config.Delivery.Throttle.InitialConnections,
            InitialMessagesPerMinute = config.Delivery.Throttle.InitialMessagesPerMinute,
        });
        // Replicas on one database share the per-destination ceilings and tell each other what remote destinations did (ReplicaCoordinationService runs it).
        ReplicaCoordinator? replicaCoordinator = storage.Replicas is { } coordination
            ? new ReplicaCoordinator(coordination, deliveryOptions.Owner, clock, destinationThrottle, routeHealth, log: log)
            : null;

        var services = new DeliveryServices
        {
            Storage = storage,
            Clock = clock,
            Mx = mx,
            Tls = tls,
            TlsPolicies = new TlsPolicyTable(deliveryOptions.DefaultTls),
            Pool = pool,
            Routes = routes,
            Throttle = destinationThrottle,
            Limits = limits,
            Retry = new RetrySchedule(BuildRetryOptions(config.Delivery)),
            Dkim = new ConfigDkimSignerProvider(storage.Config, secrets, clock, deliveryOptions.DkimCacheTtl),
            TlsReports = collector,
            Secrets = secrets,
            Verp = verp,
            Log = log,
        };
        var delivery = new DeliveryEngine(new DeliveryProcessor(services, deliveryOptions, new DsnService(storage, clock, deliveryOptions)), services, deliveryOptions);
        engine = delivery;

        var webhooks = new WebhookDispatcher(storage.Webhooks, storage.Config, secrets, config.Webhooks, clock, log, new EndpointDisabledNotifier(storage, clock, log));

        var tlsJournal = collector is null ? null : new TlsReportJournal(collector, storage.Config, clock, log);
        TlsReportSender? reports = tlsJournal is null
            ? null
            : new TlsReportSender(tlsJournal, storage.Config, new TlsRptRecordLookup(dns), new TlsRptHttpsSender(), storage.Intake, clock, config.Hostname, config.Tls.ReportContact ?? "postmaster@" + config.Hostname, log);

        AcmeRenewalService? acme = null;
        AcmeHttpChallengeListener? acmeHttpListener = null;
        if (config.Acme.Enabled)
        {
            // DNS-01 needs a DNS provider and so credentials; without them (Acme:Challenge Auto or Http01) the server answers HTTP-01 itself.
            if (acmeDnsOverride is null && config.Acme.HasDnsCredentials())
            {
                string token = config.Acme.CloudflareApiToken ?? File.ReadAllText(config.Acme.CloudflareApiTokenFile!).Trim();
                acmeDnsOverride = new CloudflareDnsChallengeProvider(new HttpClient(), token);
            }

            Http01Challenges? http01 = null;
            if (config.Acme.UsesHttp01())
            {
                http01 = new Http01Challenges(storage.Config, clock, log);
                http01.ExpectListener();
                acmeHttpListener = new AcmeHttpChallengeListener(http01, config.Acme.Http01BindAddress, config.Acme.Http01ListenPort, http01, log);
            }

            acme = new AcmeRenewalService(storage.Config, secrets, acmeRunnerOverride ?? new CertesOrderRunner(log: log), acmeDnsOverride, config.Acme, clock, log, http: http01);
        }

        var runtime = new EggMailRuntime
        {
            KeysProtectedAtRest = Mta.Host.Secrets.SecretsFactory.KeysProtectedAtRest(config.Secrets, storage.Config),
            Config = config, Storage = storage, Clock = clock, Log = log, Secrets = secrets, Certificates = certificates, Verp = verp,
            Submission = submission, AuthThrottle = throttle, SmtpServer = smtp, Delivery = delivery, Webhooks = webhooks, Dns = dns,
            Inbound = inbound, InboundConfiguration = inboundConfiguration,
            Pool = pool, Routes = routes, Limits = limits, Acme = acme, AcmeHttpListener = acmeHttpListener, TlsReports = reports, Health = routeHealth, DestinationThrottle = destinationThrottle, ReplicaCoordinator = replicaCoordinator,
            CounterPersistence = counterPersistence, TlsJournal = tlsJournal, TlsCollector = collector,
        };
        runtime._owned.Add(certificateMeters);
        if (replicaCoordinator is not null)
        {
            runtime._owned.Add(replicaCoordinator);
        }

        if (acmeHttpListener is not null)
        {
            runtime._owned.Add(acmeHttpListener);
        }

        runtime._owned.Add(pool);
        runtime._owned.Add(smtp);
        return runtime;
    }

    /// <summary>
    /// The listener as the server runs it. With inbound mail on, the port-25 listener (the one of role Bounce, or Inbound) is an MX receiver: role Inbound, the inbound size ceiling and recipient cap, and no
    /// AUTH. With it off, a listener configured as Inbound is the bounce listener it replaces (nothing receives mail that was not switched on). Submission listeners are never touched.
    /// </summary>
    internal static SmtpListenerOptions InboundListener(SmtpListenerOptions listener, InboundReceiveOptions inbound)
    {
        if (listener.Role == ListenerRole.Submission)
        {
            return listener;
        }

        if (!inbound.Enabled)
        {
            return listener.Role == ListenerRole.Inbound ? CopyWithRole(listener, ListenerRole.Bounce) : listener;
        }

        return CopyWithRole(listener, ListenerRole.Inbound, inbound.Ceilings.MaxMessageBytes, inbound.MaxRecipients + 1);
    }

    private static SmtpListenerOptions CopyWithRole(SmtpListenerOptions l, ListenerRole role, long? maxMessageSize = null, int? maxRecipients = null) => new()
    {
        Name = l.Name, BindAddress = l.BindAddress, Port = l.Port, Mode = l.Mode, Role = role, AuthRequired = false, Enabled = l.Enabled, AllowInsecureAuth = l.AllowInsecureAuth,
        MaxMessageSize = maxMessageSize ?? l.MaxMessageSize, MaxRecipients = maxRecipients ?? l.MaxRecipients,
    };

    /// <summary>The built-in ladder unless <c>Delivery:RetryDelays</c> overrides it (used by operators with unusual needs and by the chaos tests).</summary>
    internal static RetryScheduleOptions? BuildRetryOptions(DeliverySection delivery)
    {
        if (delivery.RetryDelays.Count == 0)
        {
            return null;
        }

        var first = delivery.RetryDelays[0];
        var last = delivery.RetryDelays[^1];
        return new RetryScheduleOptions
        {
            Delays = delivery.RetryDelays,
            RepeatInterval = last,
            FinalAttemptMargin = TimeSpan.Zero,
            FirstConnectionRetryDelay = first,
            GreylistMinDelay = first,
            GreylistMaxDelay = last,
            ThrottleMinDelay = first,
            MinHint = TimeSpan.FromMilliseconds(1),
            MaxHint = last,
            MaxDelay = last > TimeSpan.FromHours(8) ? last : TimeSpan.FromHours(8),
        };
    }

    internal static IDnsResolver CreateDns(MtaConfig config)
    {
        var servers = config.Dns.Servers.Count > 0
            ? config.Dns.Servers.Select(ParseEndpoint).ToList()
            : SystemDnsConfiguration.Discover(allowPublicFallback: true).Servers.ToList();
        var options = new DnsResolverOptions { Servers = servers, RequestDnssecOk = config.Dns.RequestDnssec, TrustAuthenticatedData = config.Dns.TrustAuthenticatedData };
        return new DnsClient(new UdpTcpDnsTransport(options), options);
    }

    /// <summary>Parses <c>1.1.1.1</c>, <c>1.1.1.1:53</c>, <c>2606:4700::1111</c> and <c>[2606:4700::1111]:53</c>.</summary>
    internal static System.Net.IPEndPoint ParseEndpoint(string text)
    {
        text = text.Trim();
        if (System.Net.IPAddress.TryParse(text, out var bare))
        {
            return new System.Net.IPEndPoint(bare, 53);
        }

        if (System.Net.IPEndPoint.TryParse(text, out var endpoint))
        {
            return endpoint;
        }

        throw new InvalidOperationException($"Dns:Servers entry '{text}' is not an IP address with an optional port.");
    }

    /// <summary>
    /// Writes the state kept in memory for speed to the storage: the sending counters and the TLS-RPT counters. Called every few seconds by the runtime state service,
    /// at shutdown, and when a backend switch quiesces this instance (so the bundle holds the last counts). A failure is logged and the data stays in memory for the next call.
    /// </summary>
    public async Task FlushRuntimeStateAsync(CancellationToken ct, bool includeTlsReports = true)
    {
        try
        {
            await CounterPersistence.FlushAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.Write(MtaLogLevel.Warning, "state", "could not persist the sending counters; they stay in memory for the next flush", ex);
        }

        if (includeTlsReports && TlsJournal is { } journal)
        {
            try
            {
                await journal.FlushAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Log.Write(MtaLogLevel.Warning, "state", "could not persist the TLS-RPT counters; they stay in memory for the next flush", ex);
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var o in _owned)
        {
            await o.DisposeAsync().ConfigureAwait(false);
        }
    }
}
