# Use cases

[← Documentation index](../README.md#documentation)

Common command patterns depending on who you’re sharing with.

## Sharing with Netgate TAC Support

```bash
# On the firewall (recommended for TAC)
/usr/local/sbin/diag_sanitize.php /conf/config.xml > /conf/config_sanitised.xml

# Off-box: additional anonymisation before sharing further
pfsense-redactor config_sanitised.xml support-safe.xml --keep-private-ips --no-redact-domains
```

## Sharing with AI tools

Use `--aggressive` if you have third-party packages or aren’t sure where secrets live.

```bash
# Topology-preserving anonymisation (private IPs are kept visible by default with --anonymise)
pfsense-redactor config.xml ai-ready.xml --anonymise --aggressive
# Now safe to upload to AI tools for configuration analysis
```

```bash
# Anonymise everything (including private IPs)
pfsense-redactor config.xml ai-ready.xml --anonymise --no-keep-private-ips --aggressive
# Now safe to upload to AI tools for configuration analysis
```

## Vendor/MSP Handoffs

```bash
# Option A: Preserve private IPs for troubleshooting context
pfsense-redactor config.xml vendor-share.xml --anonymise
```

```bash
# Option B: Anonymise everything (including private IPs) for stricter privacy
pfsense-redactor config.xml vendor-share.xml --anonymise --no-keep-private-ips
```

## Security Audits

```bash
# Preview what will be redacted before sharing
pfsense-redactor config.xml --dry-run-verbose
```

## Automated Compliance Workflows

```bash
# CI/CD integration for automated sanitisation
pfsense-redactor $INPUT_CONFIG $OUTPUT_CONFIG --aggressive --fail-on-warn
```

## Relationship to pfSense built-in sanitisation

pfSense includes a built-in configuration sanitisation script:

```bash
/usr/local/sbin/diag_sanitize.php /conf/config.xml > /conf/config_sanitised.xml
```

This official tool runs **on the firewall itself** and is primarily intended for safely sharing configurations with Netgate support. It removes high-value secrets (password hashes, pre-shared keys, certificates, etc.) while preserving the original network topology.

**pfsense-redactor is complementary, not a replacement.**

| Built-in `diag_sanitize.php`         | pfsense-redactor                                                  |
| ------------------------------------ | ----------------------------------------------------------------- |
| Runs on pfSense only                 | Runs anywhere (workstation, CI, automation)                       |
| PHP, internal to pfSense             | Python, standalone, MIT-licensed                                  |
| Fixed sanitisation behaviour         | Configurable redaction and anonymisation                          |
| Removes secrets                      | Removes secrets **and** can anonymise IPs, domains, MACs and URLs |
| Best suited to Netgate support (TAC) | Best suited to vendors, consultants, AI tools and forums          |

pfsense-redactor exists to cover use cases where:

- the configuration has already been exported,
- you do not wish to run additional tooling on the firewall,
- or you require **privacy-preserving anonymisation** in addition to basic secret removal.

Both tools share the same goal: preventing accidental disclosure of sensitive information when sharing pfSense configurations.

## Comparison with Alternatives

<details>
<summary>Comparison with Alternatives</summary>

| Feature                 | pfsense-redactor  | Generic XML Tools | Manual Redaction | Built-in diag_sanitize.php |
| ----------------------- | ----------------- | ----------------- | ---------------- | -------------------------- |
| pfSense-aware structure | ✅                | ❌                | ⚠️ Manual        | ✅                         |
| Runs off-firewall       | ✅                | ✅                | ✅               | ❌ (pfSense only)          |
| Network anonymisation   | ✅                | ❌                | ⚠️ Error-prone   | ❌                         |
| Topology preservation   | ✅                | ❌                | ⚠️ Error-prone   | ✅                         |
| Configurable modes      | ✅ multiple modes | ❌                | N/A              | ❌ Fixed                   |
| CIDR allow-lists        | ✅                | ❌                | ⚠️ Error-prone   | ❌                         |
| CI/CD integration       | ✅                | ⚠️                | ⚠️ Error-prone   | ❌                         |
| Cross-platform          | ✅                | ⚠️                | ✅               | ❌                         |
| WireGuard/IPsec aware   | ✅                | ❌                | ⚠️               | ✅                         |
| Zero dependencies       | ✅                | ⚠️ Varies         | ✅               | ✅                         |

</details>
