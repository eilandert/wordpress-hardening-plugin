# ---------------------------------------------------------------------------
# Shared CRS base image.
#
# Both the Apache (ModSecurity v2) and the Angie (libmodsecurity3 / v3)
# integration images derive their rule set from THIS single image, so both
# engines parse byte-for-byte identical CRS + plugin files. A config-parse
# regression (e.g. an invalid transformation like the AH00526 `t:uppercase`
# bug) therefore fails the build on *both* engines, which is exactly the
# guarantee the old nginx-only CI lacked.
#
# Layout produced:
#   /opt/crs/crs-setup.conf            CRS tuning (from crs-setup.conf.example)
#   /opt/crs/rules/*.conf              upstream CRS rules
#   /opt/crs/plugins/*                 upstream plugin slots + THIS plugin
#   /opt/crs/crs-main.conf             the include chain both engines load
#   /opt/crs/modsecurity.conf          engine settings (DetectionOnly for FTW)
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim

# Pin the OWASP CRS version. Overridable: --build-arg CRS_VERSION=vX.Y.Z
ARG CRS_VERSION=v4.7.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${CRS_VERSION}" \
      https://github.com/coreruleset/coreruleset.git /opt/crs \
 && rm -rf /opt/crs/.git \
 && cp /opt/crs/crs-setup.conf.example /opt/crs/crs-setup.conf

# Drop in this plugin (config + before/after + .data files).
COPY plugins/ /opt/crs/plugins/

# Engine config: DetectionOnly so blocking rules still log (go-ftw asserts on
# the audit log) without 403-ing the synthetic test traffic. Serial audit log
# in the native (v2/v3 compatible) format that go-ftw parses.
COPY tests/integration/crs/modsecurity.conf /opt/crs/modsecurity.conf

# The include chain. Order matters: CRS setup -> plugin phase config ->
# plugin "before" rules -> CRS rules -> plugin "after" rules. The two CI
# SecActions enable the GeoIP + IP-reputation features (disabled by default)
# so their rules are actually exercised, mirroring the prior integration.yml.
COPY tests/integration/crs/crs-main.conf /opt/crs/crs-main.conf

# Sanity: every file the chain references must exist.
RUN test -f /opt/crs/crs-setup.conf \
 && test -f /opt/crs/plugins/wordpress-hardening-before.conf \
 && ls /opt/crs/rules/*.conf >/dev/null
