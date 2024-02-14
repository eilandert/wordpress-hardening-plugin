# Wordpress-hardening-plugin
This plugin contains extra rules to enhance the security of wordpress installations with the OWASP Core Rule Set.
It's encouraged to install the wordpress-exclusions-rules-plugin as well, as we only add extra blocks in this plugin.

The idea is to enhance the security of WordPress while minimizing the impact on PHP/SQL performance and eliminating the need for additional security plugins without interfering with wordpress or owasp.

What this plugin does so far:
- Block xmlrpc.php access (configurable, default: block) (PL1)
- Block user enumeration (configurable, default: block) (PL1)
- Block the wp-json restapi (configurable, default: non-block) (PL1)
- Block directory listing in /wp-content/* and /wp-includes/* (PL1)
- Block direct php access in /wp-content/* and /wp-includes/* (PL1>
- Block direct file access to some files in / and other files/directories (PL1)
- Block other interpreters like .pl/.lua/.py/.sh (PL2)
- Block nasty files in uploads/* (PL1)
- Block access to sensitive files like .db/.orig/.sql/.log/.git (PL1)
- Block access to "/wp-json" (exact match, the api still works) (PL1)

Raincheck list:
- wp-cron.php (configurable)
- wp-login.php, lock out ip after $x failures for $y time (configurable)
- block inclusion attacks for index.php
- lock out accounts named "admin" (configurable)
- whitelist server ip to access the blocked wp-cron/wp-json/xmlrpc paths

## Requirements
- CRS Version 4.0 or newer
- ModSecurity compatable Web Application Firewall

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


