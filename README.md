# Wordpress-hardening-plugin / modsecurity (CRS4.0+)
![Integration tests](https://github.com/eilandert/wordpress-hardening-plugin/actions/workflows/integration.yml/badge.svg) ![Integration tests](https://github.com/eilandert/wordpress-hardening-plugin/actions/workflows/lint.yml/badge.svg)

This plugin contains extra rules to enhance the security of wordpress installations with the OWASP Core Rule Set.
It's encouraged to install the wordpress-exclusions-rules-plugin as well, as we only add extra blocks in this plugin.

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
- IP-based rate limiting for wp-login.php (configurable, default: 5 attempts per 60 seconds) (PL1)
- GeoIP-based access control for wp-login.php (configurable, default: disabled) (PL1)
- Automatic IP reputation blocklist blocking all requests from listed IPs/CIDRs (configurable, default: disabled) (PL1)

## IP Whitelisting

The blocked endpoints (`xmlrpc.php`, `wp-json`, `wp-cron.php`) allow traffic from localhost and RFC 1918 private IP ranges by default:

- `127.0.0.0/8` (localhost)
- `10.0.0.0/8` (private)
- `172.16.0.0/12` (private)
- `192.168.0.0/16` (private)

This allows internal systems (cron jobs, monitoring, load balancers) to access these endpoints while blocking external attacks. You can customize the whitelist per endpoint in `wordpress-hardening-config.conf` (see the examples provided).

## Configuration

All features are **enabled by default** with sensible defaults. To override defaults or disable specific protections, uncomment the corresponding `SecAction` line in `plugins/wordpress-hardening-config.conf`.

**Important note on `block_admin_login`**: This rule blocks login attempts that use the **literal username "admin"** — it does NOT block all administrator accounts. Only WordPress installations with a user named exactly "admin" will be affected.

## IP-Based Rate Limiting

The plugin includes IP-based rate limiting for `wp-login.php` to prevent brute force attacks.

**How it works:**
- Tracks all POST requests to `/wp-login.php` per IP address
- Locks out an IP after exceeding the attempt threshold
- Whitelist prevents rate limiting for trusted IPs (localhost + RFC 1918 by default)

**Default settings:**
- **Enabled by default** (`ratelimit_login_enabled`)
- **5 login attempts** per IP (`ratelimit_login_attempts`)
- **60 second window** (`ratelimit_login_window`)
- **Whitelisted IPs**: `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`

**Customization:**

Uncomment these in `plugins/wordpress-hardening-config.conf` to override defaults:

```bash
# Reduce to 3 attempts per 30 seconds
#SecAction "id:9522051,phase:1,nolog,pass,t:none,setvar:tx.wphard.ratelimit_login_attempts=3"
#SecAction "id:9522053,phase:1,nolog,pass,t:none,setvar:tx.wphard.ratelimit_login_window=30"

# Add datacenter IPs to whitelist (space-separated CIDR, spaces as %20)
#SecAction "id:9522055,phase:1,nolog,pass,t:none,setvar:tx.wphard.ratelimit_login_whitelist_ips=127.0.0.0/8%20 10.0.0.0/8%20 172.16.0.0/12%20 192.168.0.0/16%20 203.0.113.0/24"

# Disable rate limiting entirely
#SecAction "id:9522049,phase:1,nolog,pass,t:none,setvar:tx.wphard.ratelimit_login_enabled=0"
```

## GeoIP-Based Access Control for wp-login.php

Blocks access to `wp-login.php` for clients from countries not in the allowed list. No GeoIP database is required on the WAF — the upstream proxy sets a standard header and ModSecurity reads it.

**How it works:**
- Upstream proxy (Cloudflare, nginx + ngx_http_geoip2_module, HAProxy, etc.) sets `CF-IPCountry` or `X-GeoIP-Country` with the client's 2-letter ISO 3166-1 country code
- Requests without a recognized country header are **allowed through** (fail-open)
- Loopback and RFC 1918 addresses are always whitelisted
- Allowed countries are listed one per line in `plugins/wordpress-hardening-login-countries.data`

**Default settings:**
- **Disabled by default** (`geoip_login_enabled=0`)

> **Security note:** The country header is trusted unconditionally. Only enable this feature behind a proxy that sets and strips client-supplied values for these headers.

**To enable:**
1. Uncomment the SecAction in `plugins/wordpress-hardening-config.conf`:
   ```bash
   SecAction "id:9522052,phase:1,nolog,pass,t:none,setvar:'tx.wphard.geoip_login_enabled=1'"
   ```
2. Populate `plugins/wordpress-hardening-login-countries.data` with the ISO codes of countries you want to allow (one per line):
   ```
   NL
   DE
   GB
   ```

## IP Reputation Blocklist

Blocks **all requests** (not just login attempts) from IP addresses listed in `plugins/wordpress-hardening-ip-reputation.data`. Supports individual IPs and CIDR ranges. No external API or database required — the blocklist is a plain text file you populate from threat intelligence feeds or your own data.

**How it works:**
- Client IP sourced from `X-Forwarded-For` (preferred, for proxied traffic) or `REMOTE_ADDR`
- Uses ModSecurity's `@ipMatchFromFile` operator — supports IPv4, IPv6, and CIDR notation
- Loopback and RFC 1918 addresses are always whitelisted
- Applies globally (all URIs, not just `wp-login.php`)

**Default settings:**
- **Disabled by default** (`ip_reputation_enabled=0`)
- Data file ships with `192.0.2.0/24` (RFC 5737 documentation range used for CI tests) — replace with real entries in production

> **Security note:** `X-Forwarded-For` is trusted unconditionally. Only enable this feature behind a proxy that controls the header.

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

## Future Features (Raincheck list)

These features are planned but not yet implemented:
- IP-based rate limiting for other endpoints (wp-admin, xmlrpc, etc.)

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
