# Security

[← Documentation index](../README.md#documentation)

## Threat model

The failure that matters is **failing to redact**. Output is produced in order to
be shared outside the firewall, so a missed secret is disclosed to whoever
receives it. Everything below follows from that: where a judgement call exists,
this tool over-redacts rather than under-redacts, and surfaces what it chose to
keep so you can audit it.

Verify before sharing: see [verifying output](verifying-output.md), and see
[the benchmark](benchmark.md) for measured coverage and known gaps.

## What gets redacted

Secrets are found by **element name**, not by value shape, because a real SNMP
community (`public`) or WPA passphrase looks like ordinary text. Matching is
substring-based, since the spellings that leak are the concatenated ones
pfSense and its packages actually emit: `rocommunity`, `radiussecret`,
`passwordagain`. A deny-list handles the false positives that creates
(`keylen`, `certref`, `password_type`).

### Certificate references are resolved, not guessed

Elements named for a certificate are a special case, because they hold two quite
different things. `<crt>` holds the material. `<ssl_ca_cert>` and HAProxy's
`<ha_certificates>` usually hold a `refid` pointing at a certificate defined
elsewhere in the same file, and those references are worth keeping: they are not
secret, and they let whoever reads the config follow its structure.

Telling them apart by length is the obvious approach and the wrong one. Anything
short enough passes, whatever it actually is.

Since 1.2.0 the file is scanned for every `<refid>` it declares before redaction
starts, and a short value in a certificate-named element is kept only if it
resolves against that list. Values that resolve to nothing are redacted. Where a
value carries several references, as HAProxy's can, all of them have to resolve;
a partial match means the value is not purely a reference list.

A config with no `<refid>` anywhere therefore loses its short certificate
values. That is deliberate. Absent evidence that a value is a reference, the
threat model says treat it as a secret.

### Attribute values

pfSense itself does not use XML attributes, but third-party packages may, and
the tool accepts whatever XML it is given. Attributes are handled two ways:

- **By name.** An attribute named for a secret is redacted, as an element would
  be. `--redact-descriptions` extends this to free-prose names such as `note`
  and `descr`.
- **By value.** Since 1.2.0, an attribute whose name says nothing but whose
  *value* looks like key material is reported among the retained high-entropy
  values, and redacted under `--aggressive`.

The second exists because name matching cannot see a blob in an innocuously
named attribute, so before 1.2.0 such a value was invisible to `--fail-on-warn`
as well: a CI gate passed on a file whose own output had never mentioned it. It
reports rather than redacts by default because no pfSense config examined in
testing uses attributes at all, and rewriting values on that evidence would
over-redact for everyone.

Credentials embedded in URLs are handled separately:

| Location | Default | `--aggressive` |
| --- | --- | --- |
| `user:password@host` | password redacted | same |
| `?token=…` query parameter | redacted | same |
| Path token on a known webhook host | redacted | same |
| Path segment on any other host | kept | redacted |

Path segments are kept by default because pfBlockerNG feed URLs legitimately
carry long path components that redaction would destroy, and a corrupted config
is its own kind of failure.

The exception is endpoints where the path token *is* the credential, since
anyone holding the URL can post as that integration. For those the token is
redacted in every mode:

| Endpoint | Matched as |
| --- | --- |
| Slack | `hooks.slack.com` + `/services/` |
| Discord | `discord.com`, `discordapp.com`, `ptb.`/`canary.` variants + `/api/webhooks/` |
| Telegram | `api.telegram.org` + `/bot` |
| Teams | `outlook.office.com`/`outlook.office365.com` + `/webhook/` |
| Teams (per-tenant) | any `*.webhook.office.com` + `/webhookb2/` |

Hosts are matched **exactly** apart from Teams, which puts the tenant in a
subdomain and so is matched on the suffix `.webhook.office.com`. The leading
dot is what stops `notwebhook.office.com` qualifying. Either way the path
prefix must match too, so an ordinary `discord.com/channels/…` link is
untouched. Everything else still needs `--aggressive`.

Self-hosted tools such as Mattermost are deliberately absent: their webhooks
sit at `/hooks/<token>` on whatever host the operator chose, so there is no
host to match on.

Recognised credential formats in path segments include AWS access key IDs
(exactly 20 characters), Telegram bot tokens (`bot<id>:<secret>`, where the
colon defeats a naive base64 test) and Slack/Discord tokens with no digits in
them.

Before 1.1.2 this depended on the element name: `<webhook_url>` matched the
secret-name pattern and was redacted whole, but the same URL in `<slack_url>`,
`<notifyurl>` or a plain `<url>` kept its token unless `--aggressive` was used.

## Input handling

Input declaring a `<!DOCTYPE>` is **refused**. pfSense never emits one, so its
presence means the file did not come from pfSense untouched.

This is deliberately not described as an XXE fix. Python's
`xml.etree.ElementTree` does not resolve external entities. A `SYSTEM` entity
raises `ParseError`, so there is no file disclosure and no SSRF. What it does
do is expand *internal* entities, where a few hundred bytes of nested
definitions expand to gigabytes. The whole XML prolog is scanned rather than a
fixed-size prefix, so a declaration cannot hide behind a large comment, and a
prolog beyond 1 MiB is refused outright to bound the work a hostile file can
demand.

## Sharing the output

> **Never restore the redacted file to pfSense.**

Redacted output is for **analysis only**, because:

- CDATA and comments are removed by XML parser
- PEM blocks and binary data are collapsed
- Some optional metadata fields may be stripped

Always keep the **original secure copy**.

## Path safety

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
