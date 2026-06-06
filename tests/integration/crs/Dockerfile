# ---------------------------------------------------------------------------
# Shared CRS base image.
#
# Both the Apache (ModSecurity v2) and the Angie (libmodsecurity3 / v3)
# integration images derive their rule set from THIS single image, so both
# engines parse byte-for-byte identical CRS + plugin files. A config-parse
# regression (e.g. an invalid transformation like the AH00526 `t:uppercase`
# bug) therefore fails the build on *both* engines.
#
# CRS comes from the SAME apt repo as production (deb.myguard.nl), so the
# test rule set matches what mail.myguard.nl actually runs.
#
# Layout produced (unchanged contract for the engine images):
#   /opt/crs/crs-setup.conf            CRS tuning (from crs-setup.conf.example)
#   /opt/crs/rules/*.conf              CRS rules (from the modsecurity-crs pkg)
#   /opt/crs/plugins/*                 THIS plugin (config + before/after + data)
#   /opt/crs/crs-main.conf             the include chain both engines load
#   /opt/crs/modsecurity.conf          engine settings (DetectionOnly for FTW)
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

# Production ships modsecurity-crs from deb.myguard.nl. Pin the package
# version; overridable via --build-arg if the repo moves forward.
ARG CRS_DEB_VERSION=4.27.0+3.260603-3myguard1~bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
 && install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL https://deb.myguard.nl/deb.myguard.nl.gpg -o /tmp/mg.key \
 && (gpg --dearmor < /tmp/mg.key > /etc/apt/keyrings/deb.myguard.nl.gpg 2>/dev/null \
      || cp /tmp/mg.key /etc/apt/keyrings/deb.myguard.nl.gpg) \
 && echo 'deb [signed-by=/etc/apt/keyrings/deb.myguard.nl.gpg] https://deb.myguard.nl bookworm main' \
      > /etc/apt/sources.list.d/myguard.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      "modsecurity-crs=${CRS_DEB_VERSION}" \
 && rm -rf /var/lib/apt/lists/* /tmp/mg.key

# Re-home the package tree into the /opt/crs layout the engine images expect.
RUN mkdir -p /opt/crs/plugins \
 && cp /etc/modsecurity/crs/crs-setup.conf.example /opt/crs/crs-setup.conf \
 && cp -a /etc/modsecurity/crs/rules /opt/crs/rules

# Drop in this plugin (config + before + after + .data files).
COPY plugins/ /opt/crs/plugins/

# Note: as of audit-round-5 the plugin ships a real *-after.conf carrying
# the phase:1 scoring rules per CRS convention. The zzz-ci-noop-after.conf
# stub previously created here is no longer needed.

# Engine config + the include chain (DetectionOnly, serial audit log, the
# go-ftw log marker, GeoIP/IP-rep enabled — see the files themselves).
COPY tests/integration/crs/modsecurity.conf /opt/crs/modsecurity.conf
COPY tests/integration/crs/crs-main.conf /opt/crs/crs-main.conf

# Sanity: every file the chain references must exist.
RUN test -f /opt/crs/crs-setup.conf \
 && test -f /opt/crs/plugins/wordpress-hardening-before.conf \
 && ls /opt/crs/rules/*.conf >/dev/null
