using System.Security.Cryptography;
using System.Text;
using Mta.Core;
using Mta.Host.Configuration;
using Mta.Storage;

namespace Mta.Host.Hosting;

/// <summary>
/// The relay (smarthost) given by the deployment (<c>EGGMAIL_RELAY</c>, keys <c>Delivery:Relay:*</c>) is kept in the config store as the relay route named
/// <see cref="RelaySection.RouteName"/>, so the delivery engine, the dashboard and a backend switch see it like any other route. It is a fallback after
/// direct delivery, for every recipient domain, as relay routes always are. At every start the configuration is authoritative for host, port, TLS mode and
/// login of that route; priority, the domains it carries and its enabled flag stay as an administrator set them in the dashboard. Removing the configuration
/// removes the route. The route is recognised by its fixed id, not by its name: a route an administrator made with the same name is never changed or deleted
/// (the start is refused with the reason instead), and neither is any other route.
/// </summary>
public static class RelayBootstrap
{
    /// <summary>Priority of the route when it is created (the dashboard can change it).</summary>
    public const int DefaultPriority = 100;

    /// <summary>A fixed id for the route: replicas that start together write the same record instead of two.</summary>
    public static readonly Guid RouteId = new(SHA256.HashData(Encoding.UTF8.GetBytes("eggmail:" + RelaySection.RouteName))[..16]);

    /// <summary>Returns a problem to report (the server then refuses to start), or null.</summary>
    public static async Task<string?> ApplyAsync(MtaConfig config, IConfigStore store, ISecretProtector protector, IMtaLog log, CancellationToken ct)
    {
        RelaySection relay = config.Delivery.Relay;
        IReadOnlyList<RelayRouteRecord> routes = await store.GetRelayRoutesAsync(ct).ConfigureAwait(false);
        RelayRouteRecord? existing = routes.FirstOrDefault(r => r.Id == RouteId);
        if (string.IsNullOrWhiteSpace(relay.Address))
        {
            if (existing is not null)
            {
                await store.DeleteRelayRouteAsync(existing.Id, ct).ConfigureAwait(false);
                log.Write(MtaLogLevel.Information, "startup", $"The relay route '{RelaySection.RouteName}' was removed: EGGMAIL_RELAY (Delivery:Relay:Address) is no longer set.");
            }

            return null;
        }

        if (routes.Any(r => r.Id != RouteId && string.Equals(r.Name, RelaySection.RouteName, StringComparison.OrdinalIgnoreCase)))
        {
            return $"A relay route named '{RelaySection.RouteName}' exists that this server did not create from EGGMAIL_RELAY. Rename it in the dashboard (Relay routes) or remove EGGMAIL_RELAY.";
        }

        string address = relay.Address.Trim();
        int colon = address.LastIndexOf(':');
        string host = EnvironmentAliases.NormalizeHostname(address[..colon])!;
        int port = int.Parse(address[(colon + 1)..], System.Globalization.CultureInfo.InvariantCulture);
        string mode = string.IsNullOrWhiteSpace(relay.TlsMode) ? (port == 465 ? "implicit" : "verify") : relay.TlsMode.Trim().ToLowerInvariant();

        string? user = string.IsNullOrWhiteSpace(relay.User) ? null : relay.User.Trim();
        byte[]? protectedPassword = null;
        if (user is not null)
        {
            string password;
            if (!string.IsNullOrEmpty(relay.Password))
            {
                password = relay.Password;
            }
            else
            {
                string file = relay.PasswordFile!;
                try
                {
                    password = (await File.ReadAllTextAsync(file, ct).ConfigureAwait(false)).Trim();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    return $"The relay password file '{file}' cannot be read ({ex.Message}). Create it, or fix EGGMAIL_RELAY_PASSWORD_FILE.";
                }

                if (password.Length == 0)
                {
                    return $"The relay password file '{file}' is empty.";
                }
            }

            // Encryption is randomized: keep the stored bytes when they already hold this password, so a restart does not rewrite the route.
            if (existing?.PasswordProtected is { Length: > 0 } stored && SamePassword(protector, stored, password))
            {
                protectedPassword = stored;
            }
            else
            {
                protectedPassword = protector.Protect(Encoding.UTF8.GetBytes(password), SecretPurposes.RelayPassword);
            }
        }

        var desired = new RelayRouteRecord(
            existing?.Id ?? RouteId, RelaySection.RouteName, host, port, mode, user, protectedPassword,
            existing?.Priority ?? DefaultPriority, existing?.Enabled ?? true, existing?.Domains ?? ["*"]);
        if (existing is not null && SameRoute(existing, desired))
        {
            return null;
        }

        await store.UpsertRelayRouteAsync(desired, ct).ConfigureAwait(false);
        log.Write(MtaLogLevel.Information, "startup",
            $"Relay route '{RelaySection.RouteName}' {(existing is null ? "created" : "updated")} from the configuration: {host}:{port}, TLS mode {mode}, {(user is null ? "no login" : "login " + user)}. Direct delivery is still tried first.");
        return null;
    }

    private static bool SamePassword(ISecretProtector protector, byte[] stored, string password)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(protector.Unprotect(stored, SecretPurposes.RelayPassword), Encoding.UTF8.GetBytes(password));
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    private static bool SameRoute(RelayRouteRecord a, RelayRouteRecord b) =>
        a.Host == b.Host && a.Port == b.Port && string.Equals(a.TlsMode, b.TlsMode, StringComparison.OrdinalIgnoreCase) && a.UserName == b.UserName
        && ((a.PasswordProtected is null) == (b.PasswordProtected is null)) && (a.PasswordProtected is null || a.PasswordProtected.AsSpan().SequenceEqual(b.PasswordProtected!));
}
