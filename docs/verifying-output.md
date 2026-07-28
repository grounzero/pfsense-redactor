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
secrets, run against 1.1.1:

| Secret | gitleaks | redactor 1.1.1 (default) | redactor 1.1.2 (default) |
| --- | :--: | :--: | :--: |
| `<rocommunity>public` | ❌ | ✅ | ✅ |
| `<passphrase>CorrectHorseBattery` | ❌ | ✅ | ✅ |
| `<ldap_bindpw>Sw0rdf1sh!` | ❌ | ✅ | ✅ |
| `<access_key>` AWS key id | ❌ | ✅ | ✅ |
| `<secret_access_key>` | ❌ | ✅ | ✅ |
| `<slack_url>` webhook token | **✅** | **❌** | ✅ |

gitleaks found one of the six — and it was the one this tool was missing.
**That row is why this page exists**: the finding was reported and fixed in
1.1.2, which now redacts path tokens on known webhook hosts in every mode. An
independent scanner earned its keep on the first run.

**Why gitleaks missed the other five:** an SNMP community of `public` and a
passphrase of `CorrectHorseBattery` have no distinguishing shape; nothing about
the value says "secret". Only the element name does. It also skipped the AWS key
because `AKIAIOSFODNN7EXAMPLE` is Amazon's documented example key and is
allowlisted — worth knowing if you test with it.

That asymmetry is the point, and it did not go away with the fix. The two tools
fail in opposite directions, so a second opinion is still worth having on a
config this one has not seen.

Webhook tokens on hosts other than Slack, Discord and Telegram still need
`--aggressive`, since a long path segment on an unrecognised host is as likely
to be a feed URL as a credential.

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
