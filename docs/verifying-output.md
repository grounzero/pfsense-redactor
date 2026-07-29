# Verifying redacted output

[← Documentation index](../README.md#documentation)

Redaction is not a thing to take on trust. This page covers the checks built
into the tool, and how to get a second opinion from a scanner that fails
differently.

## 1. Read the summary, especially what was *kept*

Every run prints what it redacted. More usefully, it also reports what it
deliberately did **not**:

```
[!] 1 unrecognised high-entropy value(s) retained. Review before sharing:
    - pfsense/installedpackages/mycustompkg/config/blob
    Re-run with --aggressive to redact these automatically.
```

These are values that look like key material in elements the tool does not
recognise, typically third-party package fields. It reports the element path
rather than the value, so the warning is safe to paste into a ticket.

Since 1.2.0 attribute values are checked the same way, and appear with the
attribute named in brackets:

```
    - pfsense/installedpackages/mycustompkg/config/telemetry[@endpoint_id]
```

This warning is the direct answer to "what did you leave behind". Do not ignore
it, and re-run with `--aggressive` if any path looks like it holds a secret.

## 2. Read the independent verification

Since 1.2.2 a second component re-reads the **serialised output** — the exact
text that gets written — and reports material that should not be in it:

```
[!] Independent verification found 2 issue(s) in the output:
    - retained-private-key: document (pem-private-key, 1704 chars) - private-key PEM header in candidate output
    - retained-input-value: pfsense/installedpackages/vendor/blob (element, 44 chars) - input value present verbatim in candidate output
```

This is not the summary restated. The summary is the transformer reporting what
it chose to keep, so a class of secret the transformer cannot see is equally
invisible to it. The verifier is a separate module with its own rules, and it
looks at the output rather than at the transformer's record of it.

Two checks, deliberately different in kind:

- **Shape scan.** Private-key PEM headers, compact JWTs, credential-bearing
  URLs, and long hexadecimal or Base64 runs — including through up to three
  layers of Base64 decoding. Patterns written and maintained separately from
  the transformer's, so a mistake in one is not automatically a mistake in the
  other.
- **Input-value retention.** Every input leaf and attribute value of 16
  characters or more is checked for verbatim survival. This is the check that
  cannot inherit the transformer's blind spots, because it classifies nothing:
  it does not need to know what a value means to notice that it came out
  unchanged.

Findings carry a path, a category, a length and a reason. They never carry the
value, a prefix of it, or a hash of it — a short secret's hash is
brute-forceable and a token's prefix names its issuer — so the whole block is
safe to paste into a ticket.

### What it compares

A value made entirely of `A-Za-z0-9+/=_-` — the alphabet Base64, Base64URL, hex
and API keys share — is compared whole.

Anything else is **tokenised** and the parts are compared instead. A secret is
often not a value but part of one: a key inside `{"api_secret": "…"}`, a token
in a config line, a word in a note. Comparing only whole values found none of
them. The separators are not enumerated — every character JSON, URLs, shell and
config text use to delimit things is outside that alphabet, so a maximal run of
alphabet characters is exactly one token.

Element **tails** — the mixed-content text between one element's close and the
next element's open — are collected alongside text and attribute values. pfSense
does not emit mixed content, so this covers hand-edited and package-generated
XML, which the check previously could not see at all.

The 16-character floor does most of the false-positive work: `api_secret`,
`deploy`, `key`, `https`, `index` and essentially every English word are below
it.

### What it does not see

A secret shorter than 16 characters, or one broken across a separator, is
invisible to this check. JWTs and credential-bearing URLs are covered by the
shape scan instead, and free prose by `--redact-descriptions`.

Excluded, each by a rule asserted individually in
`tests/unit/test_output_verification.py`:

| Excluded | Why |
| --- | --- |
| The tool's own placeholders | Reporting the redaction as the leak is worse than useless |
| Allow-listed entries | The operator asked to keep them |
| Structural element names (`refid`, `uuid`, `interface`, package metadata) | References and identifiers a reader needs to follow the config |
| Absolute paths, whole or as a token | pfSense stores them in quantity and the transformer preserves them deliberately. `/` is in the alphabet because Base64 uses it, so a leading slash is the test — a Base64 token with a slash *inside* it is unaffected |
| URLs | A credential in one is caught precisely by the shape scan. What is left is the path and query, which are what the transformer preserves on purpose — pfBlockerNG feed URLs carry long path components |

Measured on the shipped sample configurations under the strongest policy, the
URL and path exclusions accounted for 16 of 25 findings on the largest, and
none of the 16 was a secret. The remainder are package names, blocklist names
and rule tags that genuinely do survive verbatim — which is the check working,
not failing.

### Advisory in 1.2.2

The result is reported; it does not yet decide whether output is written. Do
not read "no findings" as "safe to publish" — read it as "a second pass found
nothing", which is a weaker and more useful statement.

### If verification is unavailable

`redactor.py` can be copied out and run as a single file. Done that way, without
`verifier.py` beside it, the run says so:

```
[!] Independent verification unavailable: verifier.py is not importable.
    Redaction ran, but nothing re-read the output.
```

That is deliberately not silence, and deliberately not a pass. Copy `verifier.py`
alongside `redactor.py` to keep the check.

## 3. Let CI check it for you

The same warning drives an exit code, so a pipeline can gate on it:

```bash
pfsense-redactor config.xml --dry-run --fail-on-warn
```

Non-zero means either the root tag is not `pfsense`, or values were retained for
review. Nothing is written, so this is safe to run on every commit. Adding
`--aggressive` redacts those values instead of retaining them, which makes the
gate pass.

## 4. Preview before you share

```bash
pfsense-redactor config.xml --dry-run-verbose
```

Shows counts plus masked before/after examples, so you can confirm the right
things are being caught without writing a file. Samples are masked, so the
preview never prints a live secret to your terminal or CI log.

## 5. Get a second opinion

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

Measured, not assumed. gitleaks 8.30.1 against a config containing six real
secrets, run against 1.1.1:

| Secret | gitleaks | redactor 1.1.1 (default) | redactor 1.1.2 (default) |
| --- | :--: | :--: | :--: |
| `<rocommunity>public` | ❌ | ✅ | ✅ |
| `<passphrase>CorrectHorseBattery` | ❌ | ✅ | ✅ |
| `<ldap_bindpw>Sw0rdf1sh!` | ❌ | ✅ | ✅ |
| `<access_key>` AWS key id | ❌ | ✅ | ✅ |
| `<secret_access_key>` | ❌ | ✅ | ✅ |
| `<slack_url>` webhook token | **✅** | **❌** | ✅ |

gitleaks found one of the six, and it was the one this tool was missing.
**That row is why this page exists**: the finding was reported and fixed in
1.1.2, which now redacts path tokens on known webhook hosts in every mode. An
independent scanner earned its keep on the first run.

**Why gitleaks missed the other five:** an SNMP community of `public` and a
passphrase of `CorrectHorseBattery` have no distinguishing shape; nothing about
the value says "secret". Only the element name does. It also skipped the AWS key
because `AKIAIOSFODNN7EXAMPLE` is Amazon's documented example key and is
allowlisted, which is worth knowing if you test with it.

That asymmetry is the point, and it did not go away with the fix. The two tools
fail in opposite directions, so a second opinion is still worth having on a
config this one has not seen.

Webhook tokens on hosts other than Slack, Discord and Telegram still need
`--aggressive`, since a long path segment on an unrecognised host is as likely
to be a feed URL as a credential.

### A clean scan is not a clean file

Do not read "no leaks found" as proof. On this project's own 46-secret
[canary corpus](benchmark.md), gitleaks reports **no findings at all**, before
any redaction. The planted markers are low-entropy placeholder strings, which is
the same reason it misses a real SNMP community.

A scanner that finds nothing may mean the file is clean, or that the secrets do
not look like secrets. Use it to catch what this tool missed, never to certify
that nothing was missed.

## 6. Diff the two files

For a config small enough to read, nothing beats looking:

```bash
diff <(xmllint --format config.xml) <(xmllint --format redacted.xml) | less
```

Every line that did *not* change is a line you are choosing to share.

## Reporting a miss

If you find a secret that survived, please open an issue. A minimal
`config.xml` fragment with the value replaced by a marker such as
`CANARY_MYSECRET` is ideal. That is exactly the shape of
[the corpus](../tests/corpus/canary-corpus.xml), and it can be added to it so
the miss stays fixed.
