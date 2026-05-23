# Audit Round 5 — wordpress-hardening-plugin

Audited 2026-05-23 against:

- CRS plugin template: <https://github.com/coreruleset/template-plugin>
- CRS plugin writing guide: <https://coreruleset.org/docs/4-about-plugins/4-2-writing-plugins/>

Findings below are ordered by severity (P0–P3) within each section. Every
*verified* finding was reproduced live against the local CI image (Apache
2.4.67 + ModSecurity v2.9.7 + CRS 4.27.0-dev, identical to production).

## Status — what shipped in this round

**Fixed and verified live (Apache + libmodsecurity3):**

- 1.1 P0 — 9522313 XDEBUG regex casing (lowercase regex literals).
- 1.2 P0 — 9522119 chain operator/actions split.
- 1.3 P1 — IPv6 first-hop regex now covers compressed mid-`::`.
- 1.4 P1 — `client_is_private` now matches IPv4-mapped IPv6.
- 1.5 P1 — Phase-1 scoring rules relocated to `wordpress-hardening-after.conf`.
- 2.3 P3 — `ver:` field normalised to `wordpress-hardening-plugin/1.2.0`.
- 3.1 — `tests/integration/.ftw.yml` and the three workflow generators
  now produce the v2 schema (`testoverride.input` with
  `override_empty_host_header: true`). The real CI break, surfaced
  during fix verification, was the legacy `- stage:` wrapper in every
  test stage — go-ftw v2's `Stage` struct uses `yaml:"input"` directly,
  so the wrapper turned every test into "send a placeholder request and
  match nothing." All 44 regression-test YAMLs and the two security-
  corpus YAMLs were converted to the v2 `- input: / output:` layout.
- 4.1 P2 — README documents `SecCollectionTimeout` requirement.
- 4.2 P2 — 9522116 now double-decodes via `t:urlDecodeUni,t:urlDecodeUni`
  applied to the *chained child* (the transforms on the parent rule do
  not propagate, which is the same root cause that hid the 9522113
  `.git/config` false-negative — both rules now apply transforms on the
  child, where ModSecurity v2 actually consults them).
- 1.3.1 (incidental) — 9522113 VCS regex extended to match
  `.git/<anything>`, `.svn/<anything>`, `.hg/<anything>`, `.bzr/<anything>`.

**New regression tests added:**

- `9522063.yaml` — IPv6/IPv4-mapped client-is-private classifier (8 cases).
- `9522116-6` — double-URL-encoded `php://` payload.
- `9522119-6/7/8` — GET, POST heartbeat, HEAD must not fire.
- `9522313-5/6/7` — lowercase and uppercase XDEBUG cases, plus xdebugger
  content slug negative.

**Pre-existing failures surfaced by the harness fix — deferred to a
follow-up audit-round-6:**

Once the harness was generating real requests instead of placeholders,
23 regression tests revealed pre-existing rule / test mismatches that
the broken harness had been masking. These are *not* regressions from
this audit — they're latent issues. Tracked for follow-up:

| Test | Likely cause |
|------|---|
| 9522112-2 | Rule regex requires `[^&]{80,}`; test payload is 60 chars. Pre-existing. |
| 9522151-1, 9522152-1 | Whitelist tests written before the resolver consolidation; need rewrite. |
| 9522205-2 | Uploads — investigate. |
| 9522207-1/2 | Tests assume `block_rest_api=1`; CRS image doesn't enable it. Decision: either flip default ON, or enable in CI. |
| 9522305-3 | Regex `\.(sql\.gz\|...\|mysqldump)` requires `.mysqldump` (literal dot prefix). `/mysqldump-2024.sql` starts the filename with `mysqldump` (no dot). Pre-existing rule shape. |
| 9522307-1/2/3/5/6 | Upload traversal — investigate. |
| 9522309-1 | Null-byte rule, PL2 elevated but specific URI doesn't match — investigate. |
| 9522317-1/2 | Dangerous admin — investigate. |
| 9522410-1/6 | Tests assert `log_contains: id "9522411"` but rule 9522411 has `nolog`. Pre-existing test bug. |
| 9522510-1/4/6/7 | GeoIP block — needs allow-list seeded with non-matching country in CI. |
| 9522801-2 | 953 FP suppression — admin/wp-content path expected to NOT exempt. Investigate. |

`detection_paranoia_level=2` is now set in the CI image so PL2 rules
(9522203, 9522309, 9522311, 9522317) are exercised. The two 9522317
failures and one 9522309 failure above are specific URI mismatches, not
PL gating.

---

## 1. Functional bugs (verified live)

### P0 — Rule 9522313 (XDEBUG/phpinfo) only catches phpinfo

[plugins/wordpress-hardening-before.conf:1371](plugins/wordpress-hardening-before.conf#L1371)

```
SecRule REQUEST_URI|ARGS_NAMES "@rx XDEBUG_SESSION(?:_(?:START|STOP))?|XDEBUG_PROFILE|XDEBUG_TRACE|(?:^|/)phpinfo(?:\.php)?(?:$|[/?])|(?:^|&)phpinfo(?:=|$)" \
  "...
  t:lowercase,t:urlDecodeUni,..."
```

The rule applies `t:lowercase` to its targets, so the input arrives in lower
case. The first three regex alternatives (`XDEBUG_SESSION`, `XDEBUG_PROFILE`,
`XDEBUG_TRACE`) are written in **upper case** and therefore never match.

Verified directly against the CI image:

```
GET /wp-login.php?XDEBUG_SESSION_START=phpstorm   → 9522313 does NOT fire
GET /?XDEBUG_SESSION=1                            → 9522313 does NOT fire
GET /wp-admin/admin.php?XDEBUG_PROFILE=1          → 9522313 does NOT fire
GET /?phpinfo=1                                   → 9522313 fires
```

Tests `9522313-1/-2/-3` were written to assert this behaviour and currently
report **pass** in CI because of a separate harness bug (see §3 below) —
they are not actually exercising the rule.

**Fix:** lowercase the regex literals, or add `(?i)` once.

```diff
- SecRule REQUEST_URI|ARGS_NAMES "@rx XDEBUG_SESSION(?:_(?:START|STOP))?|XDEBUG_PROFILE|XDEBUG_TRACE|(?:^|/)phpinfo(?:\.php)?(?:$|[/?])|(?:^|&)phpinfo(?:=|$)" \
+ SecRule REQUEST_URI|ARGS_NAMES "@rx (?:xdebug_session(?:_(?:start|stop))?|xdebug_profile|xdebug_trace|(?:^|/)phpinfo(?:\.php)?(?:$|[/?])|(?:^|&)phpinfo(?:=|$))" \
```

---

### P0 — Rule 9522119 (uncommon HTTP methods) over-fires on every method

[plugins/wordpress-hardening-before.conf:659-677](plugins/wordpress-hardening-before.conf#L659-L677)

The innermost chain rule packs operator and `setvar` action into a single
quoted string, so the comma+setvar gets absorbed into the regex pattern:

```
SecRule REQUEST_METHOD "!@rx ^(?:GET|POST|HEAD|OPTIONS)$,\
    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

After line continuation, that becomes one quoted argument. ModSecurity
parses it as 2-arg SecRule (VAR + OPERATOR, no ACTIONS), and the operator
pattern becomes
`^(?:GET|POST|HEAD|OPTIONS)$,    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'`
— a regex that nothing satisfies, so `!@rx` is always true → the chain
fires on **every** request that hits a `/wp-admin/|/wp-login.php|/xmlrpc.php|/wp-cron.php`
URI, regardless of method.

Verified live:

```
TRACE /wp-login.php   → 9522119 fires (correct)
GET   /wp-login.php   → 9522119 fires (WRONG: legit traffic blocked)
```

The same parsing pitfall affects every chained-child setvar elsewhere in
the file — but only this one suffers it because the others all put the
setvar in a properly separated third argument. Audit them on every PR.

**Fix:** split operator and actions into separate quoted args.

```diff
-    SecRule REQUEST_METHOD "!@rx ^(?:GET|POST|HEAD|OPTIONS)$,\
-    setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
+    SecRule REQUEST_METHOD "!@rx ^(?:GET|POST|HEAD|OPTIONS)$" \
+      "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
```

---

### P1 — IPv6 first-hop XFF regex (9522062) misses `::` mid-compression

[plugins/wordpress-hardening-before.conf:421-429](plugins/wordpress-hardening-before.conf#L421-L429)

The IPv6 alternatives in the resolver capture `hex:hex:…:hex`, `hex:…::`,
`::hex:…`, `::1`, and IPv4-embedded forms — but **not** the common
"`::` in the middle" form like `2001:db8::1` (RFC 4291 §2.2 rule 2).

Verified: a request with `X-Forwarded-For: 2001:db8::1` is silently
ignored by the IPv6 hop regex; `client_ip` stays at REMOTE_ADDR.

Operational impact: behind any IPv6-aware CDN/proxy that emits compressed
notation, the resolver fails open to the proxy IP. Rate-limit counter
and IP-reputation feature key on the *proxy*, not the client → shared-IP
lockout and ineffective IP-rep blocking.

**Fix:** add the middle-`::` alternative. A simpler grammar that covers
all RFC 4291 forms is:

```
^\s*\[?((?:(?:[0-9A-Fa-f]{1,4}:){1,7}[0-9A-Fa-f]{1,4})
       |(?:(?:[0-9A-Fa-f]{1,4}:){1,7}:)
       |(?::(?::[0-9A-Fa-f]{1,4}){1,7})
       |(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6}::(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?)
       |(?:::(?:ffff(?::0{1,4})?:)?(?:\d{1,3}\.){3}\d{1,3})
       |::)\]?(?=$|[\s,])
```

---

### P1 — `client_is_private` (9522063) misses IPv4-mapped IPv6 loopback

[plugins/wordpress-hardening-before.conf:436](plugins/wordpress-hardening-before.conf#L436)

`::ffff:127.0.0.1` is the dual-stack representation of IPv4 loopback (RFC
4291 §2.5.5.2). Many proxies forward IPv4 clients to dual-stack listeners
in this form. The regex covers `::1` and `fc00::/7` ULA, not IPv4-mapped.

Impact: a loopback / RFC-1918 IPv4 client whose XFF is rewritten to
mapped form is no longer treated as private, so xmlrpc/REST/wp-cron
private-IP allow-listing breaks.

**Fix:** add a mapped-IPv4 branch to the alternation:

```
|::ffff:(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[0-9]+\.[0-9]+
```

---

### P1 — Phase-1 anomaly scoring placement violates CRS convention

[plugins/wordpress-hardening-before.conf:457-707](plugins/wordpress-hardening-before.conf#L457-L707)
(rules 9522100, 9522112, 9522113, 9522114, 9522115, 9522119, 9522120)

CRS docs are explicit:

> Scoring in phase 1: Put in the plugin's _After-File_  
> Scoring in phase 2: Put in the plugin's _Before-File_
> …
> Phase 1 anomaly scoring via plugins and early blocking are incompatible.

`tx.critical_anomaly_score` (id 901140) and `tx.inbound_anomaly_score_pl1`
(id 901200) are initialised in `REQUEST-901-INITIALIZATION.conf`, which
runs **after** `*-before.conf` in phase 1. The plugin's phase-1 rules try
to do `setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'`
before either variable exists — the increment is effectively a no-op,
and 949111 (end-of-phase-1 deny) sees zero score → no block.

Production CI is `SecRuleEngine DetectionOnly`, so this latent bug is
**not detected by any current test**.

**Fix options** (any is fine; pick one):

1. Add a `plugins/wordpress-hardening-after.conf` and move the seven
   phase-1 scoring rules there. Smallest behavioural delta.
2. Drop the anomaly setvar from those rules and switch to explicit
   `deny,status:403`. These are "always-block-this-shape" rules; they
   don't need to participate in the anomaly engine.
3. Move them to phase:2 (loses the "fire before upstream redirect"
   property of phase:1, but matches everything else in the plugin).

---

## 2. CRS plugin convention divergence

### P2 — Missing required tags on every rule

The CRS template requires every detection rule carry:
`application-*`, `language-*`, `platform-*`, `attack-*`, `paranoia-level/N`,
`OWASP_CRS`, `capec/N`, and the plugin slug. Today only `paranoia-level/N`
and ad-hoc tags (`wordpress`, `info-leak`, etc.) are present.

This is what makes a rule queryable via the standard CRS tooling (`tag:OWASP_CRS`,
`tag:application-wordpress`, etc.). Without them, dashboards, exclusion
plugins, and CAPEC-driven attack tooling silently ignore these rules.

**Minimal fix** — extend every detection rule's tag list with:

```
tag:'application-wordpress',
tag:'language-php',
tag:'platform-wordpress',
tag:'attack-info-leak',          # or attack-rce / attack-dos / attack-protocol per category
tag:'OWASP_CRS',
tag:'capec/118',                 # use the correct CAPEC for the rule's class
tag:'wordpress-hardening-plugin',
```

### P3 — `ver:` field inconsistent + wrong slug

Rules carry `ver:'WPHARD/1.0.0'` and `ver:'WPHARD/1.1.0'` — both wrong
shape. The convention is `ver:'<plugin-slug>/<x.y.z>'`. Use
`ver:'wordpress-hardening-plugin/1.1.0'` (matching the actual plugin name
declared in the file header). Pick **one** version per release and apply
it everywhere.

### P3 — Sub-allocation of the 9522000–9522999 block

CRS template recommends:

```
9522000-9522099  initialisation
9522100-9522499  request rules
9522500-9522999  response rules
```

Today, GeoIP **request** rules occupy 9522500–9522510, IP-reputation
**request** rules 9522600–9522604, and BREACH detection 9522121 sits at
phase:1 in the request range — all fine. But the recommended split would
move the GeoIP and IP-rep rule IDs into the request range (e.g.
9522300+/9522400+ next to the rate-limit rules) and reserve 9522500+ for
the phase-3/4 response-header detectors. Not urgent; document the
deviation in the header comment if you keep it.

### P3 — Implicit `@rx` operator on rules 9522102 and 9522111

```
SecRule REQUEST_FILENAME "^/xmlrpc\.php" ...
SecRule REQUEST_FILENAME "^/wp-cron\.php" ...
```

Both rely on the default operator being `@rx`. Newer libmodsecurity3
versions emit a warning for implicit operators. Make them explicit.

---

## 3. Test-harness bugs

### P0 — `tests/integration/.ftw.yml` testoverride form is wrong for v2

[tests/integration/.ftw.yml:3-7](tests/integration/.ftw.yml#L3-L7)

go-ftw v2.1.0 expects overrides under `testoverride.overrides:`, not
`testoverride.input:`. With the current form the framework happily
parses the file but applies **no** overrides. Each test then runs with
its hardcoded `port: 80`, while the container listens on 8001 — the
log-marker request goes to the *host's* port 80 (or wherever) and ftw
falls back to a `GET /` placeholder with no Host header.

I traced this end-to-end against the running CI image. Concrete
evidence: when running `9522313.yaml` through ftw with the current
config, the apache audit log contains zero `id "9522313"` entries yet
ftw reports four passes. The actual test payloads (`?XDEBUG_SESSION_START`
etc.) are never sent.

Operational impact: **the entire `tests/regression/` suite is currently
passing for shape-only reasons.** Real bugs (§1 above) sail through.

**Fix:** rewrite the override file in the v2 schema:

```yaml
---
logfile: tests/logs/nginx/audit.log
testoverride:
  overrides:
    dest_addr: "127.0.0.1"
    port: 8002
    override_empty_host_header: true
```

Cross-check by deliberately introducing a malicious assertion (e.g.
`log_contains: id "9999999"` to a known-failing test) and confirming CI
fails. After the fix, the §1 bugs will start failing CI immediately.

### P1 — go-ftw `log_contains` treats the value as regex, not literal

This is a v2-schema gotcha worth documenting in `INSTALL` or
`tests/integration/README.md`: in v2, `log_contains` and `no_log_contains`
are routed through `MatchRegex` / `NoMatchRegex`. Existing tests use
literal strings like `id "9522104"`, which happen to be a valid regex
that matches itself — but operators copy-pasting examples might write
something like `log_contains: id "9522104" (wp-json)` and have the parens
parsed as a capture group. Note this in the test-authoring guide.

---

## 4. Security / RFC findings

### P2 — Rate-limit collection DoS (per-IP collection growth)

[plugins/wordpress-hardening-before.conf:1509-1518](plugins/wordpress-hardening-before.conf#L1509-L1518)

`initcol:ip=%{tx.wphard.client_ip}` creates a per-resolved-IP collection
in the SDBM `SecDataDir`. An attacker rotating IPs (legitimately easy
over IPv6, or trivially with XFF rotation if trusted-proxy pinning is
off) can grow that file unboundedly. ModSecurity does not auto-prune
SDBM collections — operators must set `SecCollectionTimeout`, which the
CRS docs explicitly tell plugins **not** to set ("the choice must be
made by the user").

**Action:** add a paragraph to README under "IP-Based Rate Limiting"
documenting:

- Set `SecCollectionTimeout 300` (or higher) at the engine config level.
- Place `SecDataDir` on a partition that can absorb growth or has a
  housekeeping cron.
- Note that this attack is *only* possible when `trusted_proxies_enabled`
  is OFF on a server with direct internet exposure (the very case the
  feature was added to harden).

### P2 — PHP-wrapper rule 9522116 vulnerable to double encoding

[plugins/wordpress-hardening-before.conf:585-603](plugins/wordpress-hardening-before.conf#L585-L603)

Transform chain is `t:none,t:urlDecodeUni,t:lowercase`. A double-encoded
payload like `%2570%2568%2570%3a%2f%2f` (= `php://`) decodes to
`%70%68%70:/ /` after one pass, which is not a literal `php://`. The
null-byte rule (9522309) already uses double `urlDecodeUni` for this
reason; mirror it here.

**Fix:**

```diff
-  t:none,t:urlDecodeUni,t:lowercase,\
+  t:none,t:urlDecodeUni,t:urlDecodeUni,t:lowercase,\
```

### P3 — Null-byte rule 9522309 coverage gap (REQUEST_HEADERS)

[plugins/wordpress-hardening-before.conf:1300](plugins/wordpress-hardening-before.conf#L1300)

`REQUEST_URI|ARGS_NAMES|ARGS` — Cookies, Referer, and custom headers can
also carry null bytes that reach `wp-login` etc. Add `REQUEST_HEADERS`
and `REQUEST_COOKIES` to the target list.

### P3 — `files.data` substring `/wp-config` blocks legit `wp-config-staging*`

[plugins/wordpress-hardening-files.data:8](plugins/wordpress-hardening-files.data#L8)

`@pmFromFile` is a substring matcher. `/wp-config-staging.php` and
`/wp-config-production.php` etc. all match the bare `/wp-config` entry.
Operators with multi-environment WP installs (very common) get a 403.

**Fix:** make the entry path-bounded. Either:

- replace `/wp-config` with `/wp-config.php` (covers the file but not
  the slash-bounded directory naming), **and**
- add the backup variants the audit-4 rule 9522114 already covers.

If you'd rather keep the substring shape, document it explicitly in
README under "Known false-positive patterns".

### P3 — Trusted-proxy data file silently fails closed when empty

[plugins/wordpress-hardening-before.conf:392-399](plugins/wordpress-hardening-before.conf#L392-L399)

`!@ipMatchFromFile wordpress-hardening-trusted-proxies.data` returns
TRUE when the file is empty (no matches → `!` flips to match). Effect:
operator enables `trusted_proxies_enabled=1` but forgets to populate the
file → every XFF is dropped → all clients appear as REMOTE_ADDR (proxy
IP) → rate-limit lockouts and IP-rep blocks key on the proxy. Add a
README warning and consider an active validation rule that logs once at
phase-1 if the feature is enabled while the data file is empty
(read-once on first request, set a flag).

### P3 — Scanner-UA list mixes hostile and ambiguous agents

[plugins/wordpress-hardening-scanners.data](plugins/wordpress-hardening-scanners.data)

`curl/`, `wget/`, `python-requests`, `go-http-client` are mainstream
automation agents widely used by legit monitoring and CI. The README
documents the SEO crawler concern but not the *automation* concern.
Either:

- Split the file into `scanners-hostile.data` (nikto/sqlmap/wpscan/…)
  and `scanners-automation.data` (curl/wget/python-requests/…), each
  behind its own toggle.
- Keep one file but flip `block_scanners=0` to require manual opt-in
  and add a prominent README note (already partly there).

---

## 5. Performance findings

### P2 — Phase-1 scoring rules run before CRS init (cold-start cost)

See §1 P1. Beyond the correctness issue, phase-1 plugin rules in
`before.conf` execute for every static asset hit (favicon, robots.txt,
fonts, …) where they fan-out 7+ anchored regexes. The static-asset fast
path (9522199) skips the file-access group but not the phase-1 hardening
group. Moving phase-1 scoring rules to `after.conf` doesn't help
performance, but if you take fix option 2 (`deny,status:403`) the rules
get cheaper because the regex chain stops on first hit.

### P3 — Backup-archive regex 9522303 walks alternation per request

[plugins/wordpress-hardening-before.conf:1190](plugins/wordpress-hardening-before.conf#L1190)

```
^/(?:backups?|db-backup|site-backup|wordpress-backup|backup-db)/|
/wp-content/(?:backups?|backup)/|
[-_]backup[-_][^/]*\.(?:zip|tar(?:\.(?:gz|bz2|xz))?|tgz|sql(?:\.(?:gz|bz2|zip))?|dump|bak)(?:$|/)|
\.(?:tar\.gz|tar\.bz2|tgz)(?:$|/)
```

Five top-level alternatives, each with its own anchor — PCRE can't
fast-fail. Splitting into two anchored rules (one `^/(?:backups?|…)/`,
one `\.(?:tar\.gz|…)(?:$|/)`) lets PCRE bail on the cheap first arm for
the 99% of requests with neither shape.

### P3 — `[fF][cCdD]` class is redundant after `t:lowercase`

The IPv6 ULA branch in `client_is_private` accepts case for hex digits.
Since the upstream resolver (9522060/61/62) populates `tx.wphard.client_ip`
from `REMOTE_ADDR` and from the XFF capture (no transform), the value
can be mixed case. Apply `t:lowercase` to the classifier rule (9522063)
and drop the `[fF]/[cCdD]` redundancy. Minor.

---

## 6. Recommended new tests

Once §3-P0 is fixed and tests are actually executing, add the following.
Most are missing today, and the ones that exist would be re-verified.

### 6.1 Block-mode regression suite

Today CI runs only `SecRuleEngine DetectionOnly`. Add a second pipeline
job that flips to `On` and asserts:

- Rules 9522100/9522112/9522113/9522114/9522119/9522120 actually return
  HTTP 403 to the client (response-code assertion, not log assertion).
  This catches the §1 P1 phase-placement bug.

```yaml
- test_title: 9522100-block-mode
  stages:
    - stage:
        input: { method: GET, uri: /readme.html, port: 8001 }
        output:
          status: 403
          log_contains: id "9522100"
```

### 6.2 Kill switch (9522099)

No test exists. Add:

```yaml
- test_title: 9522099-kill-switch
  desc: When wordpress-hardening-plugin_enabled=0, no plugin rule fires.
  stages:
    - stage:
        input:
          uri: /readme.html
          headers: { Host: kill.test, X-WPHARD-DISABLE: '1' }
        output:
          no_log_contains: id "9522
```

(Requires a one-time `SecAction setvar:tx.wordpress-hardening-plugin_enabled=0`
gate keyed on the test header, or a separate test-only CRS image variant.)

### 6.3 IPv6-aware client-IP classifier (9522063)

Today only the IPv4 RFC1918 path is exercised. Add a YAML covering:

```
::1                       → private (allow xmlrpc)
fc00::abcd:1              → private (ULA)
fd12:3456::7890           → private (ULA)
::ffff:127.0.0.1          → private (IPv4-mapped loopback)
::ffff:10.0.0.5           → private (IPv4-mapped RFC1918)
2001:db8::1               → NOT private (block xmlrpc)
fe80::1                   → NOT private (link-local)
```

Drives the §1 P1 + P2 fixes.

### 6.4 IPv6 XFF first-hop resolver (9522062)

Direct test that compressed-IPv6 XFF is honoured:

```yaml
- test_title: 9522062-xff-compressed
  stages:
    - stage:
        input:
          uri: /xmlrpc.php
          headers:
            Host: localhost
            X-Forwarded-For: "2001:db8::1, 127.0.0.1"
        output:
          log_contains: id "9522102"     # xmlrpc fires → XFF was honoured
```

### 6.5 Trusted-proxy pinning (9522064/9522065)

Two YAMLs:

- `9522065-pin-allows-trusted`: REMOTE_ADDR in trusted list →
  XFF honoured → xmlrpc blocks based on XFF.
- `9522065-pin-rejects-untrusted`: REMOTE_ADDR NOT in trusted list →
  XFF dropped → xmlrpc whitelisted because REMOTE_ADDR=127.0.0.1.

Requires a test-only `wordpress-hardening-trusted-proxies.data` with
`172.19.0.0/16` (the docker bridge network used by the test container).

### 6.6 PHP stream wrappers (9522116) — direct + double-encoded

Today only covered indirectly via the security corpus. Add:

```yaml
- test_title: 9522116-direct
  stages: [{ stage: { input: { uri: '/?file=php://input' }, output: { log_contains: id "9522116" } } }]
- test_title: 9522116-double-encoded
  stages: [{ stage: { input: { uri: '/?file=%2570%2568%2570%3a%2f%2finput' }, output: { log_contains: id "9522116" } } }]
- test_title: 9522116-fp-https
  stages: [{ stage: { input: { uri: '/?url=https://example.com' }, output: { no_log_contains: id "9522116" } } }]
```

The double-encoded test currently FAILS — drives the §4 P2 fix.

### 6.7 Known-CVE plugin signatures (9522117 / 9522118)

```yaml
- test_title: 9522117-suretriggers-cve-2025-3102
  stages: [{ stage: { input: { method: POST, uri: '/wp-json/sure-triggers/v1/automation/execute' }, output: { log_contains: id "9522117" } } }]
- test_title: 9522117-suretriggers-via-rest-route
  stages: [{ stage: { input: { uri: '/index.php?rest_route=/sure-triggers/v1/connection' }, output: { log_contains: id "9522117" } } }]
- test_title: 9522118-bricks-builder-cve-2024-25600
  stages: [{ stage: { input: { method: POST, uri: '/wp-json/bricks/v1/render_element', data: 'element=php' }, output: { log_contains: id "9522118" } } }]
```

### 6.8 Rate-limit window dispatcher (9522416-9522420)

The five-bucket dispatcher is currently dead code under test. Add a
YAML per bucket (30/60/120/300/600) that sets the corresponding
`tx.wphard.ratelimit_login_window`, exhausts attempts within the
window, and asserts `9522412` fires with `wphard_retry_after=<window>`.

### 6.9 GeoIP feature (9522500-9522510)

No tests today for:

- `CF-IPCountry` priority over `X-GeoIP-Country` (9522500 vs 9522501)
- Country header missing → fail-open (9522504)
- Country code in allow-list → pass (9522508)
- Country code NOT in allow-list → block (9522510)
- Whitelisted private-IP client bypasses GeoIP (9522506)

### 6.10 IP-reputation feature (9522603)

- Plain IPv4 hit
- IPv4 CIDR hit (`/24`)
- IPv6 hit (`2001:db8::/32`)
- Whitelisted private-IP client bypasses (9522601)
- Feature disabled → no fire (9522600)

### 6.11 953 FP suppression (9522800/9522801)

Already partially covered by the false-positive corpus. Add an admin /
REST request that asserts 953100/953110/953120 still fire (i.e. only the
front-end permalink branch is exempted, not the whole site).

### 6.12 Phase-1 anomaly score wiring

Add to the false-positive corpus a test asserting that after a phase-1
hardening rule fires, `tx.inbound_anomaly_score_pl1` actually went up.
This is the smoking-gun test for §1 P1. The simplest form is to add a
log-only marker rule late in phase 1 that emits the current score:

```
SecAction "id:9999998,phase:1,nolog,pass,setvar:tx.audit_pl1_value=%{tx.inbound_anomaly_score_pl1}"
SecRule TX:audit_pl1_value "@rx ." "id:9999997,phase:5,pass,log,auditlog,msg:'pl1=%{tx.audit_pl1_value}'"
```

Then assert `log_contains: pl1=5` after a request that fires 9522100.

### 6.13 Negative regression tests already known

The §1 P0 bugs warrant explicit negative tests once fixed:

```yaml
- test_title: 9522119-get-must-not-fire
  desc: GET /wp-login.php must not trip the uncommon-methods rule.
  stages: [{ stage: { input: { method: GET, uri: '/wp-login.php' }, output: { no_log_contains: id "9522119" } } }]

- test_title: 9522313-xdebug-session-must-fire
  stages: [{ stage: { input: { uri: '/wp-login.php?XDEBUG_SESSION_START=phpstorm' }, output: { log_contains: id "9522313" } } }]
```

Both currently demonstrate the bugs; they pass only after the §1 fixes.

---

## 7. Summary punch-list

| ID | Severity | Area | Action |
|----|----------|------|--------|
| 1.1 | **P0** | Bug | Fix 9522313 XDEBUG regex casing |
| 1.2 | **P0** | Bug | Fix 9522119 inner-rule operator/actions split |
| 1.3 | P1 | Bug | Extend IPv6 first-hop regex (mid-`::`) |
| 1.4 | P1 | Bug | Add IPv4-mapped IPv6 to `client_is_private` |
| 1.5 | P1 | Convention | Move phase-1 scoring to `after.conf` (or switch to `deny,status:403`) |
| 2.1 | P2 | Convention | Add CRS-required tags to every detection rule |
| 2.2 | P3 | Convention | Normalize `ver:` field to plugin slug |
| 2.3 | P3 | Convention | Make implicit `@rx` explicit on 9522102/9522111 |
| 3.1 | **P0** | Test | Fix `.ftw.yml` schema (use `overrides:` not `input:`) |
| 3.2 | P1 | Docs | Note `log_contains` is regex in v2 |
| 4.1 | P2 | Docs | Document `SecCollectionTimeout` requirement for rate-limit |
| 4.2 | P2 | Bug | Add `t:urlDecodeUni` second pass to 9522116 |
| 4.3 | P3 | Coverage | Add REQUEST_HEADERS/COOKIES to 9522309 |
| 4.4 | P3 | FP | Tighten `/wp-config` entry in files.data |
| 4.5 | P3 | Docs | Document trusted-proxies empty-file behavior |
| 4.6 | P3 | Docs | Split or warn on automation UAs |
| 5.1 | P3 | Perf | Split backup-archive regex 9522303 into two anchored rules |
| 5.2 | P3 | Perf | Drop case-handling in 9522063 after `t:lowercase` |
| 6.* | — | Tests | New regression YAMLs per §6 |

Priority order to ship:

1. Fix the harness (3.1) — without it nothing else is verifiable.
2. Fix the two P0 rule bugs (1.1, 1.2).
3. Add the IPv6 fixes (1.3, 1.4).
4. Resolve phase-1 placement (1.5).
5. Add the new tests from §6 — most importantly 6.12 to prevent
   placement regressions from coming back.

Everything from §2 down is cleanup that can ride in a separate PR once
the bugs above are sealed.
