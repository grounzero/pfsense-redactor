# Examples

## Before and after

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

| Purpose                      | Command                                  |
| ---------------------------- | ---------------------------------------- |
| Support & AI review          | `--keep-private-ips --no-redact-domains` |
| Topology map w/o identifiers | `--anonymise`                            |
| Nuke everything              | `--aggressive`                           |
