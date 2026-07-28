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
copy of the configuration, and until 1.3.0 a single mistyped flag was enough to
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
| `--inplace`              | Overwrite input file with redacted output. **Requires `--force`** since 1.3.0; refused on a hard-linked file |
| `--force`                | Overwrite output file if it already exists; also the required consent for `--inplace`                   |
| `--allow-absolute-paths` | Allow absolute file paths (relative paths only by default for security)                                 |

### Assurance

| Flag             | Description                                                                                                     |
| ---------------- | --------------------------------------------------------------------------------------------------------------- |
| `--fail-on-warn` | Exit non-zero, and produce no output, if the root tag is wrong, values were retained, or verification found anything |
| `--strict`       | Fail-closed mode for output intended for public sharing. See below                                              |
| `--report-json`  | Write a machine-readable assurance report. Paths, kinds, lengths and counts only — never a value                 |

#### `--strict`

Intended for output that may be read by anyone, indefinitely. It is a mode with
no silent failure path, not a guarantee of safety — see
[security](security.md#strict-mode) for what it does and does not establish.

Strict mode:

- implies `--aggressive` and `--redact-descriptions`
- runs the independent verifier and **produces no output at all** if it finds
  anything, or if it could not run
- ignores allow-list files found in the working directory or home directory,
  and says so; `--allowlist-file` is the only way in
- refuses `--inplace`, an unsupported root element, a configuration schema
  version outside the range the tool has been exercised against, a document
  nesting more than 400 elements deep, and any element too large to process
- writes through the same atomic `0600` writer as every other mode

```bash
pfsense-redactor config.xml public.xml --strict --report-json report.json
```

### Exit codes

Every non-zero value is still non-zero, so an integration that only tests for
success is unaffected.

| Code | Meaning                                                                    |
| ---- | -------------------------------------------------------------------------- |
| 0    | Clean output produced                                                      |
| 1    | Usage error — the command line asks for something incoherent               |
| 2    | Input rejected: unparseable, unsupported schema, too deeply nested, oversized |
| 3    | A sensitive value was retained (under `--fail-on-warn` or `--strict`)      |
| 4    | Independent verification found something, or could not run                 |
| 5    | Reading or writing a file failed                                           |
| 6    | Internal processing failure                                                |

`argparse` exits **2** of its own accord for a malformed command line — an
unknown flag, a missing positional — which is the same value as *input
rejected*. Both mean "what you gave me cannot be used", they are
distinguishable from stderr, and suppressing argparse's convention would be
worse than the overlap.

### Report schema

```json
{
  "schema_version": 1,
  "tool": {"name": "pfsense-redactor", "version": "1.4.0"},
  "input": {"sha256": "…", "bytes": 48213, "root_tag": "pfsense",
            "config_version": "23.1", "config_version_supported": true},
  "mode": {"strict": true, "aggressive": true, "redact_descriptions": true,
           "anonymise": false, "fail_on_warn": false, "dry_run": false,
           "allowlist_files": []},
  "verdict": "clean",
  "verification": {"available": true, "clean": true},
  "counts": {"secrets_redacted": 42, "certificates_redacted": 6,
             "ips_redacted": 18, "domains_redacted": 9,
             "identifiers_anonymised": 0, "high_entropy_retained": 0,
             "oversized_text": 0, "verifier_findings": 0},
  "retained": [],
  "findings": [],
  "exit_code": 0
}
```

A finding looks like:

```json
{"id": "retained-private-key",
 "path": "pfsense/installedpackages/example/vendorblob",
 "kind": "pem-private-key",
 "length": 1679}
```

The report never contains a retained value, a prefix of one, decoded content, a
full credential-bearing URL, or a hash of a secret. A short secret's hash is
brute-forceable, so publishing one publishes the secret.

The `sha256` under `input` is a digest of the **input file**, which the operator
already has. It identifies which file the report describes.

Reports are written through the same atomic `0600` writer as the XML, and are
written on failure as well as on success — a run that withheld output is exactly
when a caller needs to know why.

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
