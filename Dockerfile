# syntax=docker/dockerfile:1
#
# EggMail: single image, SQLite out of the box (volume at /data), PostgreSQL selected by configuration.
# Built by GitHub Actions only (see docs/release.md). The .NET build stage runs on the BUILD platform and publishes for the
# TARGET architecture, so no QEMU emulation is needed (the final stage has no RUN steps: the chiseled base has no shell).

# ---- dashboard (Node only exists in this stage; supply-chain controls: lockfile, ignore-scripts)
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS dashboard
WORKDIR /src/dashboard
COPY dashboard/package.json dashboard/package-lock.json dashboard/.npmrc ./
RUN npm ci --ignore-scripts
COPY dashboard/ ./
RUN npm run build

# ---- .NET build
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:10.0 AS build
ARG TARGETARCH
ARG VERSION=0.0.0-dev
# ReadyToRun precompiles the application assemblies: about 30 percent faster cold start for about 24 MiB more on disk (docs/release.md, DESIGN-DECIDED).
ARG READYTORUN=true
WORKDIR /src
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/ src/
# Restore + publish only the host project graph (tests and benchmarks are not needed in the image).
RUN case "$TARGETARCH" in amd64) RID=linux-x64 ;; arm64) RID=linux-arm64 ;; *) echo "unsupported arch $TARGETARCH" && exit 1 ;; esac \
 && dotnet publish src/Mta.Host/Mta.Host.csproj -c Release -r "$RID" --self-contained false \
      -p:PublishReadyToRun="$READYTORUN" -p:Version="$VERSION" -p:DebugType=none -o /out
COPY --from=dashboard /src/dashboard/dist /out/wwwroot
# The chiseled runtime has no shell, so the data directory (owned by the non-root user) is prepared here.
RUN mkdir -p /seed/data

# ---- runtime: chiseled .NET 10 with ICU (the -extra variant), non-root
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra AS final
ARG VERSION=0.0.0-dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/eggspot/EggMail" \
      org.opencontainers.image.title="EggMail" \
      org.opencontainers.image.description="Open-source, performance-first .NET outbound SMTP server" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
WORKDIR /app
COPY --from=build /out/ ./
COPY --from=build --chown=1654:1654 /seed/data /data
ENV Storage__Backend=Sqlite \
    Sqlite__DataDirectory=/data \
    DOTNET_gcServer=0 \
    DOTNET_TieredPGO=1
# Container ports (high, mapped outward): 5587 submission STARTTLS, 4465 submissions, 2525 alt STARTTLS, 2526 bounce, 8080 HTTP (probes), 8443 HTTPS.
# Port 80 is the ACME HTTP-01 challenge listener (Acme__Enabled=true without a DNS token): publish it as 80 so the certificate authority reaches it
# (docker run -p 80:80). It answers /.well-known/acme-challenge/<token> and nothing else, and listens only while ACME is enabled with HTTP-01.
# If the runtime refuses a non-root process on port 80, set Acme__HttpListenPort=8081 and publish -p 80:8081.
EXPOSE 5587 4465 2525 2526 8080 8443 80
VOLUME ["/data"]
USER $APP_UID
ENTRYPOINT ["/app/mta"]
# --start-interval checks every 2 s while starting, so the container reports "healthy" within seconds instead of after the first 30 s interval.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --start-interval=2s --retries=3 CMD ["/app/mta", "--healthcheck"]
