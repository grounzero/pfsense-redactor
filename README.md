# pfSense XML Configuration Redactor

The **pfSense XML Configuration Redactor** safely removes sensitive information from `config.xml` exports before they are shared with support, consultants, auditors, or AI tools for security analysis.

## Installation

### From PyPI (recommended)

```bash
pip install pfsense-redactor
```

> **Note:** If you encounter an `externally-managed-environment` error (common on macOS and modern Linux distributions), use one of these alternatives:
>
> **Option 1: Install with pipx (recommended for CLI tools)**
> ```bash
> brew install pipx
> pipx install pfsense-redactor
> ```
>
> **Option 2: Use a virtual environment**
> ```bash
> python3 -m venv venv
> source venv/bin/activate
> pip install pfsense-redactor
> ```
>
> **Option 3: Install in user space**
> ```bash
> pip install --user pfsense-redactor
> ```

### From Source

```bash
git clone https://github.com/grounzero/pfsense-redactor.git
cd pfsense-redactor
```

**Option 1: Development mode (recommended for contributing)**
```bash
pip install -e .
```

**Option 2: With virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

The tool preserves **network architecture and routing logic** whilst sanitising **secrets and identifiers** allowing safe troubleshooting and topology review without disclosing private data.

> Keeps firewall and routing context  
> Removes passwords, keys, public IPs (optional), tokens, certs  
> Supports anonymisation for consistent placeholder mapping  
> Understands pfSense config structures, namespaces, VPNs, WireGuard, XML attributes, IPv6 zone IDs

---

## Features

### Protects real secrets
- Passwords & encrypted passwords
- Pre-shared keys (IPSec, OpenVPN, WireGuard)
- TLS/OpenVPN static keys & certs
- SNMP community strings
- LDAP / RADIUS secrets
- API keys & tokens
- PEM blocks (RSA / EC / OpenSSH)

### Preserves network logic
- Subnets & masks (255.x.x.x always preserved)
- Router topology
- VLAN and VPN interfaces
- Firewall rules and gateways

### Smart redaction
| Data | Behaviour |
|------|----------|
| Internal IPs | Preserve with `--keep-private-ips` |
| Public IPs | Mask or anonymise |
| Email addresses | Mask or anonymise |
| URLs | Preserve structure, mask hostname |
| MAC addresses | Mask format-preserving |
| Certificates | Collapse to `[REDACTED_CERT_OR_KEY]` |

### Operational modes

| Mode | Purpose |
|------|--------|
| Default | Safe redaction for sharing logs |
| `--keep-private-ips` | Preserve private IPs (best for support/AI) |
| `--anonymise` | Replace identifiers with consistent placeholders (`IP_1`, `domain3.example`) |
| `--aggressive` | Scrub **all** fields (plugins/custom XML) |

---

## Requirements

- **Python 3.8+**

---

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

---

## Allow-lists

Allow-lists let you preserve specific well-known IPs and domains that don't leak private information.

### Default allow-list files

The tool automatically loads allow-lists from these locations (if they exist):
1. `.pfsense-allowlist` in current directory
2. `~/.pfsense-allowlist` in home directory

To disable: use `--no-default-allowlist`

### Allow-list file format

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

See [`allowlist.example`](allowlist.example) for a complete template.

### CLI allow-list flags

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

---

## Example

### Input
```xml
<openvpn>
  <server>
    <local>192.168.10.1</local>
    <tlsauth>-----BEGIN OpenVPN Static key-----ABC123...</tlsauth>
    <remote>198.51.100.10</remote>
    <remote_port>443</remote_port>
  </server>
</openvpn>
```

### Output (`--keep-private-ips`)
```xml
<openvpn>
  <server>
    <local>192.168.10.1</local>
    <tlsauth>[REDACTED]</tlsauth>
    <remote>XXX.XXX.XXX.XXX</remote>
    <remote_port>443</remote_port>
  </server>
</openvpn>
```

### Output (`--anonymise`)
```xml
<openvpn>
  <server>
    <local>IP_1</local>
    <tlsauth>[REDACTED]</tlsauth>
    <remote>IP_2</remote>
    <remote_port>443</remote_port>
  </server>
</openvpn>
```

---

## Security Notes

> **Never restore the redacted file to pfSense.**

Redacted output is for **analysis only**, because:

- CDATA and comments are removed by XML parser
- PEM blocks and binary data are collapsed
- Some optional metadata fields may be stripped

Always keep the **original secure copy**.

### Path Security

The tool includes built-in protections against malicious file path operations:

**Default behaviour (secure):**
- Only relative paths are allowed by default
- Directory traversal (`../../../etc/passwd`) is blocked
- Paths with null bytes are rejected
- Writing to system directories (`/etc`, `/sys`, `/proc`, `/Windows/System32`, etc.) is blocked
- Safe locations (home directory, current working directory, temp directories) are automatically allowed

**Using `--allow-absolute-paths`:**
- Enables absolute paths for intentional use cases
- Still blocks writes to sensitive system directories
- Still blocks directory traversal attempts
- Useful when you need to specify full paths explicitly

**Examples:**
```bash
# Safe: relative path (default)
pfsense-redactor config.xml output.xml

# Blocked: absolute path without flag
pfsense-redactor /etc/config.xml output.xml
# Error: Absolute paths not allowed (use --allow-absolute-paths)

# Blocked: directory traversal
pfsense-redactor ../../../etc/passwd output.xml
# Error: Path contains directory traversal components (..)

# Blocked: writing to system directory (even with flag)
pfsense-redactor config.xml /etc/output.xml --allow-absolute-paths
# Error: Cannot write to sensitive system directory

# Allowed: absolute path to safe location with flag
pfsense-redactor ~/config.xml ~/output.xml --allow-absolute-paths

# Blocked: in-place editing of system files
pfsense-redactor /etc/hosts --inplace --force --allow-absolute-paths
# Error: Cannot use --inplace with this file
```

**Protected system directories:**
- Unix/Linux: `/etc`, `/sys`, `/proc`, `/dev`, `/boot`, `/root`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/lib`, `/lib64`, `/var/log`, `/var/run`, `/tmp`, `/run`
- Windows: `C:\Windows`, `C:\Windows\System32`, `C:\Program Files`, `C:\ProgramData`
- Critical files: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, etc.

---

## Testing

### Dry run summary
```bash
# Statistics only
pfsense-redactor config.xml --dry-run

# Statistics with sample redactions (safely masked to avoid leaks)
pfsense-redactor config.xml --dry-run-verbose
```

**Sample output with `--dry-run-verbose`:**
```
[+] Redaction summary:
    - Passwords/keys/secrets: 10
    - Certificates: 6
    - IP addresses: 26
    - Domain names: 47

[+] Samples of changes (limit N=5):
    IP: 198.51.***.42 → XXX.XXX.XXX.XXX
    IP: 2001:db8:*:****::1 → XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX
    URL: https://198.51.***.42/admin → https://XXX.XXX.XXX.XXX/admin
    FQDN: db.***.example.org → example.com
    MAC: aa:bb:**:**:ee:ff → XX:XX:XX:XX:XX:XX
    Secret: p****************d (len=18) → [REDACTED]
    Cert/Key: PEM blob (len≈2048) → [REDACTED_CERT_OR_KEY]
```

**Sample masking policy** (prevents leaks in dry-run output):
- **IP**: Keep first and last octet/segment, mask middle (e.g., `198.51.***.42`)
- **URL**: Show full URL but mask host as above
- **FQDN**: Keep TLD and one left label, mask rest (e.g., `db.***.example.org`)
- **MAC**: Mask middle octets (e.g., `aa:bb:**:**:ee:ff`)
- **Secret**: Show length and first/last 2 chars only (e.g., `p****************d (len=18)`)
- **Cert/Key**: Just show placeholder with length (e.g., `PEM blob (len≈2048)`)

### Recommended test flags
| Purpose | Command |
|--------|---------|
| Support & AI review | `--keep-private-ips --no-redact-domains` |
| Topology map w/o identifiers | `--anonymise` |
| Nuke everything | `--aggressive` |

---

## Stats example

```
[+] Redaction summary:
    - Passwords/keys/secrets: 4
    - Certificates: 2
    - IP addresses: 11
    - MAC addresses: 3
    - Domain names: 5
    - Email addresses: 1
    - URLs: 2
```

---

## Contributing

Pull requests welcome.  Particularly:

- Additional pfSense element coverage
- Plugin XML tag packs (WireGuard, pfBlockerNG, HAProxy, Snort, ACME, FRR)
- Unit test configs

---

## Licence

MIT

