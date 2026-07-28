# pfSense XML Configuration Redactor

[![PyPI version](https://badge.fury.io/py/pfsense-redactor.svg)](https://pypi.org/project/pfsense-redactor/)
[![Python Versions](https://img.shields.io/pypi/pyversions/pfsense-redactor.svg)](https://pypi.org/project/pfsense-redactor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://github.com/grounzero/pfsense-redactor/actions/workflows/tests.yml/badge.svg)](https://github.com/grounzero/pfsense-redactor/actions/workflows/tests.yml)
[![Downloads](https://pepy.tech/badge/pfsense-redactor)](https://pepy.tech/project/pfsense-redactor)

Redact secrets from a pfSense `config.xml` so you can share it — with Netgate
support, a vendor, a forum, or an AI tool — without handing over your passwords,
keys and network layout.

Unlike generic XML redaction, it understands pfSense structures: IPsec, OpenVPN,
WireGuard, captive portal, and the package configs where credentials actually
hide.

## Install

```bash
pip install pfsense-redactor
```

Pure Python standard library, no dependencies, Python 3.9+.

<details>
<summary>If pip reports <code>externally-managed-environment</code></summary>

Common on macOS and recent Linux distributions. Any of these work:

```bash
pipx install pfsense-redactor          # recommended for CLI tools
```

```bash
python3 -m venv venv && source venv/bin/activate
pip install pfsense-redactor
```

```bash
pip install --user pfsense-redactor
```

</details>

<details>
<summary>From source</summary>

```bash
git clone https://github.com/grounzero/pfsense-redactor.git
cd pfsense-redactor
pip install -e .
```

</details>

## Quick start

**Sharing with support — keep internal addressing readable:**

```bash
pfsense-redactor config.xml redacted.xml --keep-private-ips
```

Removes secrets and public identifiers, leaves RFC 1918 addressing intact so
whoever is helping can still follow your topology.

**Sharing with a vendor, forum or AI tool — anonymise identifiers:**

```bash
pfsense-redactor config.xml redacted.xml --anonymise
```

Replaces addresses and domains with consistent placeholders, so relationships
between rules and interfaces survive while the real values do not.

**Check before you commit to it:**

```bash
pfsense-redactor config.xml --dry-run-verbose
```

Prints what would change, with samples safely masked.

**If your config sends notifications** (Slack, Discord, Telegram), add
`--aggressive` — webhook tokens live in URL paths, which are preserved by
default so package feed URLs are not destroyed. See
[security](https://github.com/grounzero/pfsense-redactor/blob/main/docs/security.md#what-gets-redacted).

## How well does it work?

Measured against a 46-secret canary corpus that ships with the repository:

| Tool | Caught |
|---|---|
| **pfsense-redactor 1.1.1** | **42 / 46** |
| ForesightCyber Config Anonymizer | 17 / 46 |
| netgate-xlsx | 11 / 46 |

The corpus was built alongside this tool, which biases it — and the four misses
are documented rather than hidden. Run it yourself:

```bash
pfsense-redactor tests/corpus/canary-corpus.xml --stdout --aggressive \
  | grep -oE 'CANARY_[A-Z0-9_]+' | sort -u
```

Full method, caveats and per-secret results in
[the benchmark](https://github.com/grounzero/pfsense-redactor/blob/main/docs/benchmark.md).

## Before you share the output

> **Never restore a redacted file to pfSense.** Comments, CDATA and some
> metadata do not survive the round trip. Keep your original.

Read the run summary — it reports high-entropy values it deliberately *kept*,
with their element paths, so you can audit them. For a second opinion from a
scanner that fails differently, see
[verifying output](https://github.com/grounzero/pfsense-redactor/blob/main/docs/verifying-output.md).

## Documentation

| | |
|---|---|
| [CLI reference](https://github.com/grounzero/pfsense-redactor/blob/main/docs/cli-reference.md) | Every flag, with examples |
| [Use cases](https://github.com/grounzero/pfsense-redactor/blob/main/docs/use-cases.md) | Netgate TAC, AI tools, MSP handoff, audits — and how this relates to `diag_sanitize.php` |
| [Allow-lists](https://github.com/grounzero/pfsense-redactor/blob/main/docs/allow-lists.md) | Keep specific IPs, CIDRs and domains readable |
| [Security](https://github.com/grounzero/pfsense-redactor/blob/main/docs/security.md) | Threat model, what gets redacted, path safety |
| [Verifying output](https://github.com/grounzero/pfsense-redactor/blob/main/docs/verifying-output.md) | Checking the result, and using gitleaks alongside |
| [Benchmark](https://github.com/grounzero/pfsense-redactor/blob/main/docs/benchmark.md) | Canary corpus results and known gaps |
| [Examples](https://github.com/grounzero/pfsense-redactor/blob/main/docs/examples.md) | Before/after output, statistics, testing |
| [FAQ](https://github.com/grounzero/pfsense-redactor/blob/main/docs/faq.md) | Common questions |
| [Changelog](https://github.com/grounzero/pfsense-redactor/blob/main/CHANGELOG.md) | Release history |

## Contributing

Issues and pull requests are welcome. If you find a secret that survives
redaction, that is the most valuable report there is — a minimal fragment with
the value replaced by a `CANARY_*` marker can go straight into the corpus so the
miss stays fixed.

Run the tests with:

```bash
pip install -e ".[dev]"
pytest
```

## Licence

MIT — see [LICENSE](https://github.com/grounzero/pfsense-redactor/blob/main/LICENSE).
