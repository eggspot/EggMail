using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Mta.Host.Hosting;

/// <summary>Serves the built dashboard (static files in <c>wwwroot</c>) with the strict headers its design requires, and the single-page-app fallback.</summary>
internal static class DashboardHosting
{
    private const string ContentSecurityPolicy =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";

    public static void Map(WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;
            headers["Content-Security-Policy"] = ContentSecurityPolicy;
            headers["X-Content-Type-Options"] = "nosniff";
            headers["Referrer-Policy"] = "no-referrer";
            headers["X-Frame-Options"] = "DENY";
            headers["Cross-Origin-Opener-Policy"] = "same-origin";
            if (context.Request.IsHttps)
            {
                headers["Strict-Transport-Security"] = "max-age=31536000";
            }

            await next().ConfigureAwait(false);
        });

        app.MapGet("/healthz", () => Results.Text("ok"));

        if (Directory.Exists(Path.Combine(app.Environment.ContentRootPath, "wwwroot")))
        {
            app.UseDefaultFiles();
            app.UseStaticFiles();
            app.MapFallback(async context =>
            {
                string path = context.Request.Path.Value ?? string.Empty;
                if (path.StartsWith("/api/", StringComparison.Ordinal) || path is "/readyz" or "/metrics")
                {
                    context.Response.StatusCode = StatusCodes.Status404NotFound;
                    return;
                }

                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.SendFileAsync(Path.Combine(app.Environment.WebRootPath, "index.html")).ConfigureAwait(false);
            });
        }
    }
}
