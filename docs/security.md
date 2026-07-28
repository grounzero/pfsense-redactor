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

Secrets are found mostly by **element name**, not by value shape, because a real
SNMP community (`public`) or WPA passphrase looks like ordinary text. Matching is
substring-based, since the spellings that leak are the concatenated ones
pfSense and its packages actually emit: `rocommunity`, `radiussecret`,
`passwordagain`. A deny-list handles the false positives that creates
(`keylen`, `certref`, `password_type`).

Element names and attribute names are classified by **one** pattern. They were
two, and they disagreed: `bearer`, `cookie` and `signature` were secrets only as
attribute names, `credentials`, `privkey`, `psk`, `passphrase`, `licensekey` and
`community` only as element names. A name means the same thing wherever it
appears, so there is now a single predicate with the deny-list applied
consistently to both.

Short names that are common substrings of innocent ones — `auth`, `bearer`,
`cookie`, `signature` — are matched on word boundaries. `author`, `authserver`,
`enable_cookie` and `signature_algorithm` are not credentials and are left
alone.

`<digest>` and `<hash>` are decided by their value rather than their name.
pfSense writes `<digest>SHA384</digest>` to select an IPsec algorithm and the
reader needs it; the same element name can also hold a digest. A closed list of
algorithm names is preserved and everything else in those elements is treated as
a secret.

### Key material is not a judgement call

Three things are redacted on the strength of the **value alone**, in every mode,
whatever element or attribute holds them and whether or not the name means
anything to the tool:

- **Private-key PEM material.** `PRIVATE KEY`, `RSA`/`EC`/`DSA`/`ED25519 PRIVATE
  KEY`, `ENCRYPTED PRIVATE KEY`, `OPENSSH PRIVATE KEY`, `SSH2 ENCRYPTED PRIVATE
  KEY`, `PGP PRIVATE KEY BLOCK` and OpenVPN's `STATIC KEY`. A public key or a
  certificate is not one of these and is unaffected.
- **The same material through an encoding.** Base64 and Base64URL values are
  decoded to a bounded depth of 3 and re-examined. An encoding is not a
  protection, and a package that stores its key base64-encoded is not thereby
  storing something else.
- **Compact JWTs.** `header.payload.signature`, recognised either by the `eyJ`
  prefix or by the first segment decoding to a JOSE header.

These carry no over-redaction risk to weigh, which is why they are removed
rather than reported. Everything else the tool cannot name keeps the report-only
default described under [opaque values](#opaque-values), where the
false-positive argument genuinely applies.

Decoding is bounded in every dimension — source length, decoded size, depth, and
the total number of decode operations per value — because decoding
attacker-influenced text without limits is its own vulnerability. Decoded
content is inspected in memory and discarded: it is never logged, never sampled
and never placed in an error message.

### Opaque values

A value the tool cannot name is judged on shape, and this is the only heuristic
of the three. It must be at least 32 characters, free of whitespace, and
Base64- or hex-shaped:

| Shape | Rule |
| --- | --- |
| Hex, 32 characters or more | Treated as opaque. 32 hex characters is a 128-bit key or digest whatever subset of the alphabet it uses |
| Base64, 36 characters or more | Treated as opaque regardless of character classes |
| Base64, 32 to 36 characters | Must mix character classes — the band where an ordinary word collides with an encoded one |

Every band also requires Shannon entropy above 2 bits per character, so an
all-zero field, a run of padding and `abababab…` are not reported. UUIDs are
excluded by shape: they are 36 characters of hex and hyphens, pfSense uses them
as object identifiers, and none of them is a secret.

Before 1.2.1 all three bands required two of {digit, upper, lower}, so an
all-lowercase token, an all-uppercase token and a digest spelled only in `a-f`
were neither redacted **nor reported** — invisible to `--fail-on-warn` and to the
summary as well as to the output.

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
  values, and redacted under `--aggressive`. Since 1.2.1 the two unambiguous
  cases — private-key PEM and JWTs — are redacted here in every mode, on the
  same reasoning as for elements.

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

## Output safety

Where the output goes, and how it gets there. Separate from path safety below,
which asks whether a path is *allowed*; this asks what writing to it would do to
files that already exist.

### Verify, then write

Output is produced in this order:

```text
parse -> transform in memory -> serialise candidate
      -> verify candidate -> decide -> write
```

Nothing reaches a file or stdout before the verdict. Until 1.5.0 the write
happened first and the verdict was returned afterwards, so `--fail-on-warn`
exited non-zero *after* `_write_output` had already produced the file — the gate
reported the problem and did not prevent the artefact. A CI job that failed the
build still left the file in the workspace, and in any `upload-artifact` step
that ran regardless.

A failed gate now produces nothing: no output file, no XML on stdout, and no
temporary file. Use `--dry-run` to see the same retained paths and verification
findings without producing anything, which is what it was always for.

### Atomic writes

Output is written to a temporary file in the **destination directory**, at mode
`0600` before any bytes are written, then flushed, `fsync`ed, closed, and moved
onto the destination with `os.replace`. The directory is `fsync`ed afterwards
where the platform supports it.

The destination therefore holds either its previous content or the complete new
content. It is never a truncated mixture. `tree.write()` opened the target for
writing — truncating it — and only then began serialising, so any failure after
that point left a partial file. Under `--inplace` that file was the operator's
configuration: measured at 7,889 bytes reduced to 36.

Temporary files are removed on every failure path, including `KeyboardInterrupt`.

`0600` is a POSIX guarantee. On Windows, permissions are ACLs and `os.chmod`
only controls the read-only bit, so the restrictive mode is not claimed there.

### Destinations that are refused

| Destination | Why |
| --- | --- |
| The input file | Redacting a file over itself destroys the only copy of the secrets. Compared on device and inode, so `config.xml`, `./config.xml`, a symlink and a hard link are all caught |
| A symbolic link | The write would follow it to a file you did not name, and the replacement would then remove the link |
| A file with more than one name | Atomic replacement creates a new inode, so the other name would keep the previous — unredacted — content |

`--inplace` is the deliberate exception to the first, and requires `--force`. It
is refused on a hard-linked file for the third reason: before 1.5.0 the write
went through the link and every name saw the redacted content; it now cannot,
and a silently stale copy of an unredacted config is worse than a refusal.

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
