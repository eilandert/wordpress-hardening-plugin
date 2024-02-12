# Wordpress-hardening-plugin
This plugin contains extra rules to enhance the security of wordpress installations with the OWASP Core Rule Set.

It's possible (and encouraged) to install the wordpress-exclusions-rules-plugin as well, as we only add extra blocks in this plugin.

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


