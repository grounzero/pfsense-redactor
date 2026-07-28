# Verifying redacted output

Redaction is not a thing to take on trust. This page covers the checks built
into the tool, and how to get a second opinion from a scanner that fails
differently.

## 1. Read the summary — especially what was *kept*

Every run prints what it redacted. More usefully, it also reports what it
deliberately did **not**:

```
[!] 1 unrecognised high-entropy value(s) retained. Review before sharing:
    - pfsense/installedpackages/mycustompkg/config/blob
    Re-run with --aggressive to redact these automatically.
```

These are values that look like key material in elements the tool does not
recognise — typically third-party package fields. It reports the element path
rather than the value, so the warning is safe to paste into a ticket.

This warning is the direct answer to "what did you leave behind". Do not ignore
it, and re-run with `--aggressive` if any path looks like it holds a secret.

## 2. Preview before you share

```bash
pfsense-redactor config.xml --dry-run-verbose
```

Shows counts plus masked before/after examples, so you can confirm the right
things are being caught without writing a file. Samples are masked — the
preview never prints a live secret to your terminal or CI log.

## 3. Get a second opinion

An independent secret scanner such as [gitleaks](https://github.com/gitleaks/gitleaks)
is worth running over the output, because it fails in the opposite direction to
this tool:

- **pfsense-redactor keys off element names.** `<rocommunity>`, `<passphrase>`,
  `<ldap_bindpw>` are secrets because of what they are called, whatever they
  contain.
- **gitleaks keys off value shape.** It matches AWS key formats, Slack webhook
  URLs, PEM blocks and high-entropy strings, whatever element they sit in.

```bash
pfsense-redactor config.xml redacted.xml
gitleaks dir redacted.xml --no-banner
```

### What that actually buys you

Measured, not assumed — gitleaks 8.30.1 against a config containing six real
secrets:

| Secret | gitleaks | redactor (default) | redactor (`--aggressive`) |
|---|:--:|:--:|:--:|
| `<rocommunity>public` | ❌ | ✅ | ✅ |
| `<passphrase>CorrectHorseBattery` | ❌ | ✅ | ✅ |
| `<ldap_bindpw>Sw0rdf1sh!` | ❌ | ✅ | ✅ |
| `<access_key>` AWS key id | ❌ | ✅ | ✅ |
| `<secret_access_key>` | ❌ | ✅ | ✅ |
| `<slack_url>` webhook token | **✅** | **❌** | ✅ |

gitleaks found one of the six — and it was the one this tool misses by default.
That single row is the argument for running both.

**Why gitleaks missed the other five:** an SNMP community of `public` and a
passphrase of `CorrectHorseBattery` have no distinguishing shape; nothing about
the value says "secret". Only the element name does. It also skipped the AWS key
because `AKIAIOSFODNN7EXAMPLE` is Amazon's documented example key and is
allowlisted — worth knowing if you test with it.

**Why this tool missed the Slack token by default:** webhook credentials live in
the URL *path*, and path-segment redaction is gated behind `--aggressive`
because feed URLs (pfBlockerNG and similar) legitimately carry long path
segments that would otherwise be destroyed. The element name decides it:
`<webhook_url>` matches the secret-name pattern and is redacted whole, but
`<slack_url>`, `<notifyurl>` and a bare `<url>` are not.

If your config sends notifications, use `--aggressive`, or check those elements
by hand.

### A clean scan is not a clean file

Do not read "no leaks found" as proof. On this project's own 46-secret
[canary corpus](benchmark.md), gitleaks reports **no findings at all** — before
any redaction. The planted markers are low-entropy placeholder strings, which is
the same reason it misses a real SNMP community.

A scanner that finds nothing may mean the file is clean, or that the secrets do
not look like secrets. Use it to catch what this tool missed, never to certify
that nothing was missed.

## 4. Diff the two files

For a config small enough to read, nothing beats looking:

```bash
diff <(xmllint --format config.xml) <(xmllint --format redacted.xml) | less
```

Every line that did *not* change is a line you are choosing to share.

## Reporting a miss

If you find a secret that survived, please open an issue. A minimal
`config.xml` fragment with the value replaced by a marker such as
`CANARY_MYSECRET` is ideal — that is exactly the shape of
[the corpus](../tests/corpus/canary-corpus.xml), and it can be added to it so
the miss stays fixed.
