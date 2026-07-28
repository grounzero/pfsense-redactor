# Allow-lists

[← Documentation index](../README.md#documentation)

Allow-lists let you preserve specific well-known IPs and domains that don't leak private information.

## Default allow-list files

The tool automatically loads allow-lists from these locations (if they exist):

1. `.pfsense-allowlist` in current directory
2. `~/.pfsense-allowlist` in home directory

To disable: use `--no-default-allowlist`

## Allow-list file format

Create `.pfsense-allowlist` or use `--allowlist-file`:

```
# Comments start with #
# One item per line (IP, CIDR, or domain)

# Public DNS servers
8.8.8.8
1.1.1.1

# Cloud provider ranges
203.0.113.0/24
198.51.100.0/24

# NTP servers (suffix matching: preserves time.nist.gov and *.time.nist.gov)
time.nist.gov
pool.ntp.org

# Wildcard domains (*.example.org preserves all subdomains)
*.pfsense.org
```

See [`allowlist.example`](../allowlist.example) for a complete template.

## CLI allow-list flags

```bash
# Add specific IPs or CIDR ranges (repeatable)
--allowlist-ip 8.8.8.8 --allowlist-ip 203.0.113.0/24

# Add specific domains (repeatable, case-insensitive, supports suffix matching)
--allowlist-domain time.nist.gov --allowlist-domain pool.ntp.org

# Load from file (supports IPs, CIDRs, and domains)
--allowlist-file /path/to/allowlist.txt

# Disable default file loading
--no-default-allowlist
```

**Features:**

- **CIDR support**: `203.0.113.0/24` preserves all IPs in that range
- **Suffix matching**: `example.org` preserves `sub.example.org`, `db.corp.example.org`, etc.
- **Wildcard domains**: `*.example.org` is equivalent to suffix matching on `example.org`
- **IDNA/punycode**: Automatically handles internationalised domains (e.g., `bücher.example` ↔ `xn--bcher-kva.example`)
- **Merged sources**: All CLI flags, files, and default files are combined

**Note:** Items in allow-lists are never redacted in:

- Raw text IP/domain references
- URL hostnames
- Bare FQDNs
