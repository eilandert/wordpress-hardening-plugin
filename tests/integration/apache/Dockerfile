# ---------------------------------------------------------------------------
# Apache httpd + ModSecurity v2 (libapache2-mod-security2).
#
# This is the engine that emitted the original report:
#   AH00526: Syntax error ... Invalid transformation function: uppercase
# so this image is the faithful regression environment for that class of bug.
# `apache2ctl -t` (== apachectl configtest) is run at BUILD time: an invalid
# rule fails `docker build`, before any test runs.
# ---------------------------------------------------------------------------
ARG CRS_IMAGE=wphard-crs:latest
FROM ${CRS_IMAGE} AS crs

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      apache2 libapache2-mod-security2 ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Identical CRS + plugin tree as the nginx image.
COPY --from=crs /opt/crs /opt/crs

# Replace the distro security2 wiring with ONLY our shared chain (no double
# CRS load). The recommended unicode mapping shipped by the package is symlinked
# where ModSecurity expects it for SecUnicodeMapFile-using core rules.
RUN a2enmod security2 rewrite \
 && printf '%s\n' \
      '<IfModule security2_module>' \
      '    SecDataDir /tmp' \
      '    IncludeOptional /opt/crs/crs-main.conf' \
      '</IfModule>' > /etc/apache2/mods-enabled/security2.conf \
 && mkdir -p /var/log/modsec /var/www/html \
 && printf 'ok\n' > /var/www/html/index.html \
 && printf '%s\n' \
      'ServerName ci.local' \
      '<VirtualHost *:80>' \
      '    DocumentRoot /var/www/html' \
      '    <Directory /var/www/html>' \
      '        Require all granted' \
      '        FallbackResource /index.html' \
      '    </Directory>' \
      '</VirtualHost>' > /etc/apache2/sites-enabled/000-default.conf

# BUILD-TIME GATE: full rule parse. Fails the build on AH00526 et al.
RUN apache2ctl -t

EXPOSE 80
STOPSIGNAL SIGWINCH
CMD ["apache2ctl", "-D", "FOREGROUND"]
