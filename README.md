# Wordpress-hardening-plugin / modsecurity (CRS4.0+)
![Integration tests](https://github.com/eilandert/wordpress-hardening-plugin/actions/workflows/integration.yml/badge.svg) ![Lint](https://github.com/eilandert/wordpress-hardening-plugin/actions/workflows/lint.yml/badge.svg) ![Apache + ModSecurity v2](https://github.com/eilandert/wordpress-hardening-plugin/actions/workflows/apache-modsecurity2.yml/badge.svg) ![nginx + libmodsecurity3](https://github.com/eilandert/wordpress-hardening-plugin/actions/workflows/nginx-libmodsecurity3.yml/badge.svg) ![WAF security corpus](https://github.com/eilandert/wordpress-hardening-plugin/actions/workflows/security-corpus.yml/badge.svg)

This plugin contains extra rules to enhance the security of wordpress installations with the OWASP Core Rule Set.
It's encouraged to install the wordpress-exclusions-rules-plugin as well, as we only add extra blocks in this plugin.

More information: https://deb.myguard.nl/2026/05/wordpress-hardening-plugin-modsecurity-crs-block-attacks/

The idea is to enhance the security of WordPress while minimizing the impact on PHP/SQL performance and eliminating the need for additional wordpress security plugins without interfering with wordpress or owasp.

What this plugin does so far:
- Block xmlrpc.php access (configurable, default: block) (PL1)
- Block user enumeration (configurable, default: block) (PL1)
- Block user "admin" logins (configurable, default: block) (PL1)
- Block the wp-json restapi (configurable, default: non-block) (PL1)
- Block wp-cron.php (configurable, default: non-block) (PL1)
- Block directory listing in /wp-content/* and /wp-includes/* (PL1)
- Block direct php access in /wp-content/* and /wp-includes/* (PL1)
- Block direct file access to some files in / and other files/directories (PL1)
- Block other interpreters like .pl/.lua/.py/.sh (PL2)
- Block nasty files in uploads/* (PL1)
- Block access to sensitive files like .db/.orig/.sql/.log/.git (PL1)
- Block access to "/wp-json" (exact match, the api still works) (PL1)
- Block wp-admin theme/plugin editor access (configurable, default: block) (PL1)
- Block backup directory and archive file access (configurable, default: block) (PL1)
- Block compressed database dump access (.sql.gz/.sql.bz2/.sql.zip) (configurable, default: block) (PL1)
- Block directory traversal attempts in /wp-content/uploads/ (configurable, default: block) (PL1)
- Block null byte injection in URIs and parameters (configurable, default: block) (PL2)
- Block known security scanner user agents like nikto, sqlmap, wpscan (configurable, default: non-block) (PL2)
- Block XDebug and phpinfo debug probe parameters (configurable, default: block) (PL1)
- Block code injection patterns in wp-login.php POST parameters (configurable, default: block) (PL1)
- Block dangerous wp-admin endpoints like install.php and setup-config.php (configurable, default: non-block) (PL2)
- IP-based rate limiting for wp-login.php (configurable, default: 5 attempts per 60 seconds, replies with HTTP 429 per RFC 6585) (PL1)
- GeoIP-based access control for wp-login.php (configurable, default: disabled) (PL1)
- Automatic IP reputation blocklist blocking all requests from listed IPs/CIDRs (configurable, default: disabled) (PL1)
- Trusted-proxy pinning for X-Forwarded-For (configurable, default: disabled — backward compatible) (PL1)
- IPv6-aware client-IP resolution and private-network whitelisting (loopback + RFC 1918 + IPv6 `::1` + ULA `fc00::/7`)

## IP Whitelisting

The blocked endpoints (`xmlrpc.php`, `wp-json`, `wp-cron.php`), the rate-limit counter, the GeoIP login gate, and the IP-reputation blocklist all share a **single** client-IP resolver and a **single** "is-this-a-private-IP?" decision, so the same identity is used everywhere.

Whitelisted by default:

- `127.0.0.0/8` (IPv4 loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (IPv4 RFC 1918)
- `::1` (IPv6 loopback)
- `fc00::/7` (IPv6 Unique Local addresses, RFC 4193)

This allows internal systems (cron jobs, monitoring, load balancers) to access these endpoints while blocking external attacks.

### Client-IP resolution

`tx.wphard.client_ip` is built in phase 1 as follows:

1. Default to `REMOTE_ADDR` (the directly-connected peer).
2. If `X-Forwarded-For` is present **and trusted** (see [Trusted-Proxy Pinning](#trusted-proxy-pinning) below), take the leftmost hop. IPv4 and IPv6 first hops are both recognised; malformed values like `1.2.3.4junk` are rejected.

### Trusted-Proxy Pinning

By default the plugin honours `X-Forwarded-For` unconditionally — this is backward compatible and correct for any deployment behind a single trusted proxy (Cloudflare, nginx with `set_real_ip_from`, HAProxy). On a server with direct internet exposure, an attacker can otherwise spoof `X-Forwarded-For` and bypass the private-IP whitelist or rotate the rate-limit key.

To eliminate that footgun:

1. Populate `plugins/wordpress-hardening-trusted-proxies.data` with the public CIDRs of your real upstream proxies (one per line).
2. Enable pinning in `plugins/wordpress-hardening-config.conf`:
   ```bash
   SecAction "id:9522055,phase:1,nolog,pass,t:none,setvar:'tx.wphard.trusted_proxies_enabled=1'"
   ```

When enabled, `X-Forwarded-For` is honoured **only** if `REMOTE_ADDR` is in that list; otherwise the resolver falls back to `REMOTE_ADDR`.

## Configuration

All features are **enabled by default** with sensible defaults. To override defaults or disable specific protections, uncomment the corresponding `SecAction` line in `plugins/wordpress-hardening-config.conf`.

**Important note on `block_admin_login`**: This rule blocks login attempts that use the **literal username "admin"** — it does NOT block all administrator accounts. Only WordPress installations with a user named exactly "admin" will be affected.

## IP-Based Rate Limiting

The plugin includes IP-based rate limiting for `wp-login.php` to prevent brute force attacks.

**How it works:**
- Tracks all POST requests to `/wp-login.php` per resolved client IP
- Locks out an IP after exceeding the attempt threshold
- Whitelist prevents rate limiting for trusted IPs (loopback + private ranges, IPv4 and IPv6)
- Blocks return **HTTP 429 Too Many Requests** (RFC 6585 §4) and export `wphard_retry_after` as an env var so the webserver can add a `Retry-After` header to the response

> **⚠️ Engine support:** rate limiting relies on persistent collections
> (`initcol:ip=...` + `IP:` variables). This works reliably on **Apache +
> mod_security2 (v2.x)**. **libmodsecurity3 (the engine used by nginx /
> Angie)** has long-standing gaps in its persistent-collection
> implementation — the counter often never persists across requests and
> the rate-limit never triggers, even when the rule itself parses and
> loads correctly. If you're on libmodsec3, prefer your webserver's
> native rate-limiter (e.g. nginx/Angie's `limit_req zone=...`) for
> `/wp-login.php` and treat this plugin's rate-limiter as Apache-only.

**Default settings:**
- **Enabled by default** (`ratelimit_login_enabled`)
- **5 login attempts** per IP (`ratelimit_login_attempts`)
- **60 second window** (`ratelimit_login_window`)
- **Whitelisted IPs**: see [IP Whitelisting](#ip-whitelisting) above

**Customization:**

Uncomment these in `plugins/wordpress-hardening-config.conf` to override defaults:

```bash
# Reduce to 3 attempts
#SecAction "id:9522049,phase:1,nolog,pass,t:none,setvar:tx.wphard.ratelimit_login_attempts=3"

# Change the window (allowed values: 30, 60, 120, 300, 600 — any other value
# silently falls back to 60s)
#SecAction "id:9522050,phase:1,nolog,pass,t:none,setvar:tx.wphard.ratelimit_login_window=300"

# Disable rate limiting entirely
#SecAction "id:9522048,phase:1,nolog,pass,t:none,setvar:tx.wphard.ratelimit_login_enabled=0"
```

> **Note on the window:** `expirevar` in ModSecurity does not accept macro
> expansion in its TTL, so the plugin dispatches the configured window through
> five literal `expirevar` rules (rule IDs `9522416`-`9522420`) covering 30, 60,
> 120, 300, and 600 seconds. Any other value falls back to 60s.

### `Retry-After` response header (optional)

Rule `9522412` calls `setenv:wphard_retry_after=<seconds>` whenever it blocks
with 429. To expose that as an HTTP response header, add the following to your
webserver config:

**nginx / Angie:**
```nginx
add_header Retry-After $wphard_retry_after always;
```

**Apache (with mod_security2):**
```apache
Header always set Retry-After "%{wphard_retry_after}e" env=wphard_retry_after
```

## GeoIP-Based Access Control for wp-login.php

Blocks access to `wp-login.php` for clients from countries not in the allowed list. No GeoIP database is required on the WAF — the upstream proxy sets a standard header and ModSecurity reads it.

**How it works:**
- Upstream proxy (Cloudflare, nginx + ngx_http_geoip2_module, HAProxy, etc.) sets `CF-IPCountry` or `X-GeoIP-Country` with the client's 2-letter ISO 3166-1 country code
- Requests without a recognized country header are **allowed through** (fail-open)
- Loopback and private ranges (IPv4 RFC 1918 + IPv6 `::1` and ULA `fc00::/7`) are always whitelisted
- Allowed countries are listed one per line in `plugins/wordpress-hardening-login-countries.data`

**Default settings:**
- **Disabled by default** (`geoip_login_enabled=0`)

> **Security note:** The country header is trusted unconditionally. Only enable this feature behind a proxy that sets and strips client-supplied values for these headers.

**To enable:**
1. Uncomment the SecAction in `plugins/wordpress-hardening-config.conf`:
   ```bash
   SecAction "id:9522052,phase:1,nolog,pass,t:none,setvar:'tx.wphard.geoip_login_enabled=1'"
   ```
2. Populate `plugins/wordpress-hardening-login-countries.data` with the ISO codes of countries you want to allow (**lowercase, one per line**):
   ```
   nl
   de
   gb
   ```

   > **⚠️ Case matters.** The country header is normalised to lowercase before lookup, and `@pmFromFile` is case-sensitive. Adding `NL` (uppercase) means the allow-list never matches and every login is blocked.

## IP Reputation Blocklist

Blocks **all requests** (not just login attempts) from IP addresses listed in `plugins/wordpress-hardening-ip-reputation.data`. Supports individual IPs and CIDR ranges. No external API or database required — the blocklist is a plain text file you populate from threat intelligence feeds or your own data.

**How it works:**
- Uses the shared resolved client IP (`tx.wphard.client_ip`) — see [Client-IP resolution](#client-ip-resolution) above
- Uses ModSecurity's `@ipMatchFromFile` operator — supports IPv4, IPv6, and CIDR notation
- Loopback and private ranges (IPv4 RFC 1918 + IPv6 `::1` and ULA `fc00::/7`) are always whitelisted
- Applies globally (all URIs, not just `wp-login.php`)

**Default settings:**
- **Disabled by default** (`ip_reputation_enabled=0`)
- Data file ships with `192.0.2.0/24` (RFC 5737 documentation range used for CI tests) — replace with real entries in production

> **Security note:** `X-Forwarded-For` is trusted by default. For deployments without a proxy in front, enable [trusted-proxy pinning](#trusted-proxy-pinning) before turning this feature on, or attackers can rotate XFF to evade the blocklist.

**To enable:**
1. Uncomment the SecAction in `plugins/wordpress-hardening-config.conf`:
   ```bash
   SecAction "id:9522053,phase:1,nolog,pass,t:none,setvar:'tx.wphard.ip_reputation_enabled=1'"
   ```
2. Populate `plugins/wordpress-hardening-ip-reputation.data` with known bad IPs and CIDRs (one per line):
   ```
   198.51.100.0/24
   203.0.113.5
   2001:db8::/32
   ```

**Recommended threat intelligence sources:**
- [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt) — Don't Route Or Peer list
- [Emerging Threats](https://rules.emergingthreats.net/fwrules/) — compromised host blocklists
- [Firehol Level 1](https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset) — aggregated reputation feed

## Rule ID Map

The plugin uses the allocated range **9522000-9522999**. Major buckets:

| Range | Purpose |
|---|---|
| `9522010`-`9522055` | Config-knob `SecAction`s (commented examples in `config.conf`) |
| `9522012`-`9522050` | Default-value setters (in `before.conf`) |
| `9522060`-`9522065` | Client-IP resolver (`REMOTE_ADDR`, XFF v4/v6, trusted-proxy gate, `client_is_private`) |
| `9522099` | Plugin kill-switch (removes 9522000-9522998) |
| `9522101`-`9522111` | xmlrpc / user-enumeration / REST API / admin-login / wp-cron blocks |
| `9522150`-`9522155` | Per-group whitelist (uses `client_is_private`) |
| `9522199`-`9522207` | Static-asset fast path, direct-PHP guard, files.data, uploads, sensitive files |
| `9522300`-`9522320` | Editor / backup / DB / upload-traversal / null-byte / scanner / debug / login-injection / dangerous-admin |
| `9522400`-`9522420` | Rate-limit gate, counter, window dispatcher, 429 block |
| `9522500`-`9522510` | GeoIP header extraction + login gate |
| `9522600`-`9522604` | IP reputation gate, whitelist, block |

## Future Features (Raincheck list)

These features are planned but not yet implemented:
- IP-based rate limiting for other endpoints (wp-admin, xmlrpc, etc.)
- Native `Retry-After` header injection (today requires a one-line webserver snippet — see [Rate Limiting](#ip-based-rate-limiting))

## Requirements
- CRS Version 4.0 or newer
- ModSecurity compatible Web Application Firewall

## How to install the plugin

Please see https://coreruleset.org/docs/concepts/plugins/#how-to-install-a-plugin

## Disabling the plugin
The plugin can be disabled by uncommenting rule 9522010 inside ``plugins/wordpress-config.conf`` or by removing the includes for this plugin.

## Reporting false positives
If you find a false positive that this plugin does not cover then please open a new issue or pull request, if creating an issue then please include the following details:

1. CRS Version
2. ModSecurity/Coraza Version
3. modsec audit logs
4. what caused the false positive
