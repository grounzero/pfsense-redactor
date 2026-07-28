# CLI reference

[← Documentation index](../README.md#documentation)

## Requirements

- **Python 3.9+**

## Usage

### Basic usage

```bash
# Output filename auto-generated as config-redacted.xml
pfsense-redactor config.xml

# Or specify output filename explicitly
pfsense-redactor config.xml redacted.xml
```

### Preserve private IPs (recommended)

```bash
pfsense-redactor config.xml redacted.xml --keep-private-ips
```

### Allow-list specific IPs and domains

```bash
# Preserve specific public services (never redact)
pfsense-redactor config.xml --allowlist-ip 8.8.8.8 --allowlist-domain time.nist.gov

# Preserve entire CIDR ranges
pfsense-redactor config.xml --allowlist-ip 203.0.113.0/24

# Use an allow-list file (supports IPs, CIDRs, and domains)
pfsense-redactor config.xml --allowlist-file my-allowlist.txt
```

### Topology-safe anonymisation

```bash
pfsense-redactor config.xml redacted.xml --anonymise
```

### Allow internal DNS names

```bash
pfsense-redactor config.xml redacted.xml --no-redact-domains --keep-private-ips
```

### Aggressive mode

```bash
pfsense-redactor config.xml redacted.xml --aggressive
```

### Dry run

```bash
# Show statistics only
pfsense-redactor config.xml --dry-run

# Show statistics with sample redactions (safely masked)
pfsense-redactor config.xml --dry-run-verbose
```

### Output to STDOUT

```bash
pfsense-redactor config.xml --stdout > redacted.xml
```

### In-place (danger)

```bash
pfsense-redactor config.xml --inplace --force
```

`--force` is required, not optional. `--inplace` destroys the only unredacted
copy of the configuration, and until 1.5.0 a single mistyped flag was enough to
do it. It is also refused on a file with more than one name (a hard link),
because output is written by atomic replacement and the other name would keep
the unredacted content.

## Command-Line Flags Reference

### Version & Help

| Flag              | Description                   |
| ----------------- | ----------------------------- |
| `--version`       | Show program version and exit |
| `--check-version` | Check for updates from PyPI   |
| `-h, --help`      | Show help message and exit    |

### Input/Output

| Flag                     | Description                                                                                             |
| ------------------------ | ------------------------------------------------------------------------------------------------------- |
| `input`                  | Input pfSense config.xml file (positional argument)                                                     |
| `output`                 | Output redacted config.xml file (positional argument, optional with `--stdout`/`--dry-run`/`--inplace`) |
| `--stdout`               | Write redacted XML to stdout instead of file                                                            |
| `--inplace`              | Overwrite input file with redacted output. **Requires `--force`** since 1.5.0; refused on a hard-linked file |
| `--force`                | Overwrite output file if it already exists; also the required consent for `--inplace`                   |
| `--allow-absolute-paths` | Allow absolute file paths (relative paths only by default for security)                                 |

### Redaction Modes

| Flag                     | Description                                                                                                                                        |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--keep-private-ips`     | Keep non-global IP addresses visible (RFC1918/ULA/loopback/link-local). Netmasks and unspecified addresses (0.0.0.0, ::) always preserved          |
| `--no-keep-private-ips`  | When used with `--anonymise`, do NOT keep private IPs visible (mask all IPs)                                                                       |
| `--anonymise`            | Use consistent aliases (IP_1, domain1.example) to preserve network topology. Implies `--keep-private-ips` unless `--no-keep-private-ips` specified |
| `--aggressive`           | Broaden secret detection (high-entropy values, free-text option blocks, URL path tokens) and apply IP/domain redaction to all element text          |
| `--no-redact-ips`        | Do not redact IP addresses                                                                                                                         |
| `--no-redact-domains`    | Do not redact domain names                                                                                                                         |
| `--redact-url-usernames` | Redact usernames in URLs (default: preserve usernames, always redact passwords)                                                                    |
| `--redact-descriptions`  | Redact free-text descriptions and identifiers (`descr`, `detail`, `hostname`, `ssid`) and free-text **attributes** (`note`, `comment`, `label`, …). Off by default as these aid troubleshooting |

<details>
<summary>Allow-lists</summary>

- Allow-lists let you preserve specific well-known IPs and domains that don't leak private information.

| Flag                        | Description                                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `--allowlist-ip IP_OR_CIDR` | IP address or CIDR network to never redact (repeatable). Applies to text and URLs                                        |
| `--allowlist-domain DOMAIN` | Domain to never redact (repeatable, case-insensitive, supports suffix matching). Applies to bare FQDNs and URL hostnames |
| `--allowlist-file PATH`     | File containing IPs, CIDR networks, and domains to never redact (one per line)                                           |
| `--no-default-allowlist`    | Do not load default allow-list files (.pfsense-allowlist in current dir or ~/.pfsense-allowlist)                         |

</details>

<details>
<summary>Testing & Diagnostics</summary>

| Flag                | Description                                                             |
| ------------------- | ----------------------------------------------------------------------- |
| `--dry-run`         | Show statistics only, do not write output file                          |
| `--dry-run-verbose` | Show statistics with sample redactions (safely masked to prevent leaks) |
| `--fail-on-warn`    | Exit non-zero if the root tag is not 'pfsense', **or** if high-entropy values were retained for review. Works with `--dry-run`, so CI can check without writing |

</details>

### Output Control

| Flag            | Description                                                |
| --------------- | ---------------------------------------------------------- |
| `-q, --quiet`   | Suppress progress messages (show only warnings and errors) |
| `-v, --verbose` | Show detailed debug information                            |
