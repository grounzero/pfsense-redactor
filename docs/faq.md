# FAQ

## What does pfsense-redactor redact by default?

pfsense-redactor removes secrets such as passwords, private keys, certificates, tokens, and shared secrets.  
It also redacts public IP addresses, domains, MAC addresses, and URLs unless explicitly preserved.

## Does pfsense-redactor anonymise or just remove data?

It supports both. Redaction removes sensitive values entirely, while anonymisation replaces identifiers with consistent placeholders so topology and relationships remain clear.

## Will anonymisation break troubleshooting or topology analysis?

No. Deterministic anonymisation ensures the same identifier is always replaced with the same alias, preserving logical relationships and routing flow.

## Can I safely share the output with vendors or AI tools?

Yes. pfsense-redactor is designed for sharing configurations externally without exposing secrets or identifiable network information.  
Redacted output is for analysis only and must not be restored to pfSense.

## Does this understand pfSense-specific configuration structures?

Yes. Unlike generic XML redaction tools, pfsense-redactor understands pfSense configuration layouts, including VPNs, interfaces, gateways, and common package XML structures.

## When should I use aggressive mode?

Use `--aggressive` when sharing configurations publicly or when third-party packages may include unknown sensitive fields.

Aggressive mode broadens both secret detection and identifier rewriting. On top of the default behaviour it will:

- Redact unrecognised high-entropy values (base64/hex/PEM-shaped) in any element, rather than reporting them
- Redact free-text option blocks (`custom_options`, `userparams`, `upsd_users`, `advanced`, …) wholesale
- Redact credential-shaped URL **path** segments, such as Slack/Discord webhook tokens
- Apply IP/domain redaction to all element text, not just known fields

## Can I restore the redacted file to pfSense?

No. Redacted output is for analysis/sharing only and must never be imported back into pfSense.
