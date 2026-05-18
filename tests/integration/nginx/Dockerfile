# ---------------------------------------------------------------------------
# Angie (nginx fork) + libmodsecurity3 — a faithful mirror of production
# (mail.myguard.nl runs eilandert/angie with angie-module-http-modsecurity
# and libmodsecurity3 3.0.14). Engine + connector come straight from the
# deb.myguard.nl apt repo, so this catches v3-specific parse behaviour.
# `angie -t` is the BUILD-TIME gate.
# ---------------------------------------------------------------------------
ARG CRS_IMAGE=wphard-crs:latest
FROM ${CRS_IMAGE} AS crs

FROM debian:bookworm-slim

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
      angie angie-module-http-modsecurity libmodsecurity3 \
 && rm -rf /var/lib/apt/lists/* /tmp/mg.key

# Identical CRS + plugin tree as the Apache image.
COPY --from=crs /opt/crs /opt/crs

# Locate the connector .so the package installed and write a complete,
# minimal angie.conf that loads it and points ModSecurity at the shared chain.
RUN set -eu; \
    SO="$(find /usr/lib /usr/lib64 -name 'ngx_http_modsecurity_module.so' 2>/dev/null | head -n1)"; \
    test -n "$SO"; \
    mkdir -p /var/log/modsec /var/log/angie /var/www/html; \
    printf 'ok\n' > /var/www/html/index.html; \
    { \
      echo "load_module $SO;"; \
      echo 'user www-data;'; \
      echo 'worker_processes auto;'; \
      echo 'error_log /var/log/angie/error.log notice;'; \
      echo 'pid /run/angie.pid;'; \
      echo 'events { worker_connections 1024; }'; \
      echo 'http {'; \
      echo '    modsecurity on;'; \
      echo '    modsecurity_rules_file /opt/crs/crs-main.conf;'; \
      echo '    access_log /var/log/angie/access.log;'; \
      echo '    server {'; \
      echo '        listen 80 default_server;'; \
      echo '        server_name ci.local;'; \
      echo '        root /var/www/html;'; \
      echo '        location / { try_files $uri /index.html; }'; \
      echo '    }'; \
      echo '}'; \
    } > /etc/angie/angie.conf

# BUILD-TIME GATE: full rule parse via the real engine. Fails on bad rules.
RUN angie -t

EXPOSE 80
STOPSIGNAL SIGQUIT
CMD ["angie", "-g", "daemon off;"]
