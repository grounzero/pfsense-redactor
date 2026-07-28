# Canary corpus benchmark

[← Documentation index](../README.md#documentation)

How much of a pfSense `config.xml` does a redaction tool actually catch?

`tests/corpus/canary-corpus.xml` answers that with 46 planted secrets, each a
unique `CANARY_*` marker. A marker surviving redaction is a leak, so counting
survivors gives a score with no interpretation in between.

The corpus ships with this repository so you can check the numbers below rather
than take them on trust.

## Results

| Tool | Caught | Date tested |
| --- | --- | --- |
| **pfsense-redactor 1.2.0** | **44 / 46** (45 / 46 with `--redact-descriptions`) | 2026-07-28 |
| ForesightCyber pfSense Config Anonymizer | 17 / 46 | 2026-07-28 |
| netgate-xlsx | 11 / 46 | 2026-07-28 |

Versions were not recorded for the two comparison tools; both were the current
release at the time of testing.

The corpus file has not changed since those two tools were scored against it.
This tool's number moved because the tool changed, not because the test did.

## Which mode the score refers to

The published figure is an **`--aggressive`** result. That matters, because the
survivor count is produced by a literal `CANARY_[A-Z0-9_]+` search over the
output, and a marker the corpus author encoded is invisible to it.

Under decode-aware scanning — `tests/adversarial/decode_scan.py`, which follows
Base64 layers — the shipped corpus scores:

```text
default mode:      5 markers survive
aggressive mode:   2 markers survive  (the two documented below)
```

So the headline number is honest: under decode-aware scanning, `--aggressive`
leaves exactly the two documented survivors. What the literal count cannot
support is the *default-mode* figure, where an encoded marker survives
uncounted. Any default-mode number quoted in this project should be read as a
literal-marker count, not a decode-aware one.

`--strict` closes this differently: it does not count markers at all. Either the
material is removed, or no output is produced.

Reproduce either measurement:

```bash
# literal, the published method
pfsense-redactor tests/corpus/canary-corpus.xml --stdout --aggressive \
  | grep -oE 'CANARY_[A-Z0-9_]+' | sort -u

# decode-aware
pfsense-redactor tests/corpus/canary-corpus.xml --stdout --aggressive \
  | python tests/adversarial/decode_scan.py
```

## Read this before quoting the numbers

**The corpus was built alongside pfsense-redactor.** It grew out of bug reports
filed against this tool, and most of the 46 markers exist precisely because some
earlier release missed them. That is a real selection effect, and the section
below puts a number on it rather than leaving it as a disclaimer.

**The tools do not all share the same goal.** `netgate-xlsx` is oriented toward
exporting configuration to a spreadsheet for review rather than sanitising it
for sharing, so scoring it on secret coverage measures something it does not set
out to do. Treat its number as context, not a verdict.

**A high score is not a guarantee.** 44 / 46 on a corpus this tool was developed
against says more about regression coverage than about an unseen configuration.
Always read the output before sharing it. See
[verifying output](verifying-output.md).

## How biased is this corpus, exactly

Every released version was re-run against the corpus to find out. A marker's
origin is the release that first caught it, which is a measurement rather than a
recollection:

| Origin | Markers | What it measures |
| --- | --: | --- |
| Already caught by 1.0.10 | 15 | Coverage the tool had before the corpus existed |
| First caught in 1.1.0 | 26 | A gap 1.0.10 had |
| First caught in 1.1.1 | 1 | A gap 1.1.0 had |
| First caught in 1.1.2 | 1 | A gap 1.1.1 had |
| First caught in 1.2.0 | 2 | A gap 1.1.2 had |
| Still surviving | 1 | Deliberate; see below |
| **Contributed from outside this project** | **0** | |

So **31 of 46 markers, 67%, were planted against ground this tool did not yet
hold**, and 30 of those have since been closed. That is what the corpus is good
at: it measures regression discipline, and it demonstrably drove four releases.

**None of the 46 came from anyone else.** That is the honest limit of this
benchmark and the number worth watching. A corpus assembled by someone with a
different configuration, a different package set or a different idea of what
counts as a secret would score differently, and nothing here can tell you by how
much. If you have such a case, see [contributing a marker](#contributing-a-marker).

## What pfsense-redactor does not catch

Two markers survive `--aggressive`:

| Marker | Element | Why it survives |
| --- | --- | --- |
| `CANARY_WGPUB` | `item/publickey` | **Deliberate.** A WireGuard *public* key is not a secret; it is in `SECRET_TAG_DENYLIST`. It is identifying, so redact it with `--aggressive` if that matters to you. |
| `CANARY_ATTR_PLAIN` | `config_note[@note]` | **Caught with `--redact-descriptions`** (since 1.1.2), which covers free-text attributes as well as elements. Not caught by default, because a note is often the most useful thing in a config to whoever is reading it. No other tool in this comparison caught it in any mode. |

### The two that were closed in 1.2.0

`config/ha_certificates` and `config/ssloffloadcert` survived until 1.2.0, and
the reason is worth recording because the fix was not "add another element
name".

A short value in a certificate-named element used to be kept on the strength of
its length: under 50 characters and without a PEM header, it was assumed to be a
`refid` reference rather than key material, and references are useful to keep
because they let a reader follow the structure. That is a proxy for meaning, and
anything short enough sailed through.

Since 1.2.0 the value is resolved against the `<refid>` elements the config
actually declares. A reference that resolves is still kept. One that resolves to
nothing is redacted, because nothing in the file accounts for it. A config
carrying no `<refid>` at all therefore loses its short certificate values, which
is over-redaction in the safe direction.

`netgate-xlsx` also scores a pass on these two rows, by redacting on element
name regardless of content, which removes the resolvable references as well.

## Reproducing this

```bash
pfsense-redactor tests/corpus/canary-corpus.xml --stdout --aggressive \
  | grep -oE 'CANARY_[A-Z0-9_]+' | sort -u
```

Every marker printed is one that survived. Expect exactly two:

```
CANARY_ATTR_PLAIN
CANARY_WGPUB
```

Add `--redact-descriptions` and `CANARY_ATTR_PLAIN` goes too, leaving one.

Run the same file through any other tool and count its survivors the same way.

## Contributing a marker

The gap in this benchmark is outside input, so a marker that survives is more
useful to this project than one that does not.

New markers go in `tests/corpus/canary-corpus-supplementary.xml`, never in
`canary-corpus.xml`. The frozen corpus is what the other two tools were scored
against, and that table stops meaning anything the moment its denominator moves.
The supplementary corpus is scored separately and has no known survivors, so
anything surviving it is a bug.

Use a synthetic value, a unique `CANARY_*` marker, the reserved `.example` TLD
(RFC 2606) and documentation address ranges. A note on where the pattern comes
from is worth more than the marker itself.

## Keeping the number honest

`tests/integration/test_canary_corpus.py` pins this result in CI and fails in
both directions: a third marker surviving is a redaction regression, and one of
the two disappearing means this page is out of date. It also pins the frozen
corpus at exactly 46 markers, so the denominator cannot drift by accident. A
published coverage number that nothing enforces drifts, so it is enforced.

## Full results

<details>
<summary>All 46 planted secrets</summary>

Origin is the release that first caught the marker, measured by re-running each
released version against this corpus.

| Path | Secret type | Origin | redactor 1.2.0 | ForesightCyber | netgate-xlsx |
| --- | --- | --- | :--: | :--: | :--: |
| `user/bcrypt-hash` | password hash | 1.0.10 | ✅ | ✅ | ✅ |
| `user/md5-hash` | password hash | 1.0.10 | ✅ | ❌ | ❌ |
| `user/nt-hash` | password hash | 1.0.10 | ✅ | ❌ | ❌ |
| `user/authorizedkeys` | SSH keys | 1.1.0 | ✅ | ✅ | ✅ |
| `user/ipsecpsk` | per-user IPsec PSK | 1.1.0 | ✅ | ❌ | ❌ |
| `authserver/ldap_bindpw` | LDAP bind password | 1.0.10 | ✅ | ❌ | ❌ |
| `authserver/radius_secret` | RADIUS secret | 1.0.10 | ✅ | ❌ | ✅ |
| `zone/radiussecret` | captive portal RADIUS | 1.1.0 | ✅ | ❌ | ❌ |
| `snmpd/rocommunity` | SNMP community | 1.1.0 | ✅ | ✅ | ❌ |
| `snmpd/rwcommunity` | SNMP community | 1.1.0 | ✅ | ❌ | ❌ |
| `wpa/passphrase` | WPA PSK | 1.1.0 | ✅ | ❌ | ❌ |
| `phase1/pre-shared-key` | IPsec PSK | 1.0.10 | ✅ | ✅ | ✅ |
| `mobilekey/pre-shared-key` | IPsec mobile PSK | 1.0.10 | ✅ | ✅ | ✅ |
| `phase1/eap_password` | EAP credential | 1.1.0 | ✅ | ❌ | ❌ |
| `openvpn-client/tls` | TLS key | 1.0.10 | ✅ | ✅ | ✅ |
| `openvpn-client/auth_pass` | VPN password | 1.1.0 | ✅ | ✅ | ❌ |
| `openvpn-client/custom_options` | inline blob | 1.1.0 | ✅ | ❌ | ❌ |
| `item/privatekey` | WireGuard private key | 1.0.10 | ✅ | ✅ | ❌ |
| `item/presharedkey` | WireGuard PSK | 1.1.0 | ✅ | ❌ | ❌ |
| `item/publickey` | WireGuard public key (deny-listed) | open | ❌ | ✅ | ❌ |
| `ppp/password` | PPPoE | 1.0.10 | ✅ | ✅ | ✅ |
| `dyndns/password` | DynDNS | 1.0.10 | ✅ | ✅ | ✅ |
| `dyndns/updateurl` | token in query string | 1.1.0 | ✅ | ❌ | ❌ |
| `alias/url` | licence in query string | 1.1.0 | ✅ | ✅ | ❌ |
| `alias/detail` | credentials in free text | 1.1.0 | ✅ | ✅ | ❌ |
| `smtp/password` | SMTP | 1.0.10 | ✅ | ✅ | ✅ |
| `smtp/passwordagain` | SMTP duplicate field | 1.1.0 | ✅ | ❌ | ❌ |
| `telegram/api_key` | bot token | 1.0.10 | ✅ | ❌ | ❌ |
| `pushover/apikey` | API key | 1.0.10 | ✅ | ❌ | ❌ |
| `pushover/userkey` | user key | 1.1.0 | ✅ | ❌ | ❌ |
| `config/maxmind_key` | pfBlockerNG licence | 1.1.0 | ✅ | ✅ | ❌ |
| `item/accountkey` | ACME account key | 1.1.0 | ✅ | ❌ | ❌ |
| `a_dnsprovider/dns_cf_token` | Cloudflare token | 1.1.0 | ✅ | ❌ | ❌ |
| `config/ha_certificates` | HAProxy certs (see above) | 1.2.0 | ✅ | ❌ | ✅ |
| `config/ssloffloadcert` | HAProxy cert (see above) | 1.2.0 | ✅ | ❌ | ✅ |
| `config/influx_token` | InfluxDB token | 1.1.0 | ✅ | ❌ | ❌ |
| `config/token` | bare token | 1.1.0 | ✅ | ❌ | ❌ |
| `config/bearer_token` | bearer token | 1.1.0 | ✅ | ❌ | ❌ |
| `config/access_key` | S3 access key | 1.1.0 | ✅ | ❌ | ❌ |
| `config/secret_access_key` | S3 secret | 1.1.0 | ✅ | ❌ | ❌ |
| `config/tlspskvalue` | Zabbix PSK | 1.1.0 | ✅ | ❌ | ❌ |
| `config/upsd_users` | NUT password | 1.1.0 | ✅ | ✅ | ❌ |
| `config/userparams` | Zabbix script path | 1.1.0 | ✅ | ✅ | ❌ |
| `config/webhook_url` | Slack path token | 1.1.1 | ✅ | ❌ | ❌ |
| `config_note[@secret]` | attribute | 1.0.10 | ✅ | ❌ | ❌ |
| `config_note[@note]` | attribute free text | 1.1.2 | ❌ | ❌ | ❌ |
| **Total** | | | **44 / 46** | **17 / 46** | **11 / 46** |

`config_note[@note]` is marked ❌ because the headline run is `--aggressive`
alone. 1.1.2 catches it with `--redact-descriptions`, which is the 45 / 46 in
the results table.

</details>

## Supplementary corpus

`tests/corpus/canary-corpus-supplementary.xml` holds markers added after the
benchmark above was published, so that the frozen corpus keeps the denominator
the other two tools were measured against. It has no known survivors.

| Marker | Location | Added | Why |
| --- | --- | --- | --- |
| `CANARY_ATTR_BLOB` | `telemetry[@endpoint_id]` | 1.2.0 | Key material in an attribute whose name says nothing. `SENSITIVE_ATTR_PATTERN` matches attribute names only, so this was invisible to it and to `--fail-on-warn` alike. Now entropy-checked: reported by default, redacted under `--aggressive`. |

```bash
pfsense-redactor tests/corpus/canary-corpus-supplementary.xml --stdout --aggressive \
  | grep -oE 'CANARY_[A-Z0-9_]+' | sort -u
```

Expect no output.
