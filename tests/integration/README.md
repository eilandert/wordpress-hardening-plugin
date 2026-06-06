# Integration tests — shared CRS, two engines

A single **shared CRS + plugin** image (`crs/Dockerfile`) is consumed by two
backends so both parse byte-for-byte identical rules:

| Image            | Engine                              | Source                     | Port |
|------------------|-------------------------------------|----------------------------|------|
| `wphard-apache`  | Apache httpd + **ModSecurity v2**   | Debian `libapache2-mod-security2` | 8001 |
| `wphard-nginx`   | Angie + **libmodsecurity3** (v3)    | `deb.myguard.nl` (prod mirror)    | 8002 |

ModSecurity v2 is the engine that produced the original
`AH00526: Invalid transformation function: uppercase`. The Angie image mirrors
production (`eilandert/angie`, libmodsecurity3 3.0.14, `angie-module-http-modsecurity`).

## The regression gate

Each backend runs its config check **at image build time**
(`apache2ctl -t` / `angie -t`). An invalid rule — bad transformation,
chained `skipAfter`, unresolved marker — fails `docker build`, on **both**
engines, before any request is sent. The old CI (parser-only lint + nginx-only
upstream action) did not catch the `t:uppercase` bug; this does.

## Run locally

From the repo root:

```bash
docker compose -f tests/integration/docker-compose.yml build
docker compose -f tests/integration/docker-compose.yml up -d apache nginx

# go-ftw v2 (https://github.com/coreruleset/go-ftw)
mkdir -p tests/logs/apache tests/logs/nginx && chmod 777 tests/logs/*

ftw run -d tests/regression --config tests/integration/.ftw.yml          # apache:8001
# edit .ftw.yml port->8002 + logfile->nginx for the Angie backend, or use
# the per-backend config the CI workflow generates.

docker compose -f tests/integration/docker-compose.yml down -t 0
```

CI runs each backend as its own workflow (so each gets its own badge):

- `.github/workflows/apache-modsecurity2.yml` — **Apache + ModSecurity v2**
- `.github/workflows/nginx-libmodsecurity3.yml` — **nginx + libmodsecurity3**

Both build the same shared `wphard-crs` image, so they validate byte-identical rules on the two engines.

## Security corpus

`.github/workflows/security-corpus.yml` runs an adversarial corpus
(`tests/security/`) against both engines:

- **`bypass-evasion.yaml`** — attacks obfuscated with case / path-normalisation
  / encoding / header casing that **must still be blocked** (guards against
  bypassable rules; includes the regression for the `t:lowercase` GeoIP fix).
- **`false-positives.yaml`** — legitimate WordPress traffic (homepage,
  admin-ajax, wp-cron, REST sub-paths, assets, whitelisted login) that **must
  NOT** trip any `9522xxx` rule (guards against over-blocking).

Cross-engine on purpose: a bypass that only works on one engine still fails.

## Files

- `crs/Dockerfile` — installs the production CRS (`modsecurity-crs` from
  deb.myguard.nl, `CRS_DEB_VERSION`, default 4.27.0), re-homes it into
  `/opt/crs`, drops in `plugins/` + a CI no-op `*-after.conf`, lays down the
  include chain. Same CRS the live server runs.
- `crs/crs-main.conf` — the include order both engines load; also flips on
  the GeoIP + IP-reputation features so those rules are exercised.
- `crs/modsecurity.conf` — `SecRuleEngine DetectionOnly`, serial audit log.
- `apache/Dockerfile`, `nginx/Dockerfile` — engine images, build-time `-t` gate.
- `docker-compose.yml`, `.ftw.yml` — orchestration + harness config.
