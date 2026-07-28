# Canary corpus benchmark

How much of a pfSense `config.xml` does a redaction tool actually catch?

`tests/corpus/canary-corpus.xml` answers that with 46 planted secrets, each a
unique `CANARY_*` marker. A marker surviving redaction is a leak, so counting
survivors gives a score with no interpretation in between.

The corpus ships with this repository so you can check the numbers below rather
than take them on trust.

## Results

| Tool | Caught | Date tested |
| --- | --- | --- |
| **pfsense-redactor 1.1.1** | **42 / 46** | 2026-07-28 |
| ForesightCyber pfSense Config Anonymizer | 17 / 46 | 2026-07-28 |
| netgate-xlsx | 11 / 46 | 2026-07-28 |

Versions were not recorded for the two comparison tools; both were the current
release at the time of testing.

## Read this before quoting the numbers

**The corpus was built alongside pfsense-redactor.** It grew out of bug reports
filed against this tool — several of the 46 markers exist precisely because a
1.0.10 or 1.1.0 release missed them. It therefore covers what this tool has been
taught to look for, and a corpus assembled by either of the other projects would
likely look different and score differently. That is a real selection effect,
not a footnote.

**The tools do not all share the same goal.** `netgate-xlsx` is oriented toward
exporting configuration to a spreadsheet for review rather than sanitising it
for sharing, so scoring it on secret coverage measures something it does not set
out to do. Treat its number as context, not a verdict.

**A high score is not a guarantee.** 42 / 46 on a corpus this tool was developed
against says more about regression coverage than about an unseen configuration.
Always read the output before sharing it — see
[verifying output](verifying-output.md).

## What pfsense-redactor does not catch

Four markers survive. Two are artefacts of how the corpus is written rather than
gaps, which matters when comparing the columns:

| Marker | Element | Why it survives |
| --- | --- | --- |
| `CANARY_HAPROXYCERTS` | `config/ha_certificates` | **Corpus artefact.** The value is a short literal. Short values in certificate-named elements are deliberately preserved as *references* (a `certref`, a key id), because they help a reader understand config structure and are not key material. With real PEM or base64 content the same element redacts to `[REDACTED_CERT_OR_KEY]`. |
| `CANARY_SSLOFFLOAD` | `config/ssloffloadcert` | Same. |
| `CANARY_WGPUB` | `item/publickey` | **Deliberate.** A WireGuard *public* key is not a secret; it is in `SECRET_TAG_DENYLIST`. It is identifying, so redact it with `--aggressive` if that matters to you. |
| `CANARY_ATTR_PLAIN` | `config_note[@note]` | **Known limitation.** Free text in an XML attribute whose *name* is not sensitive. Attribute matching is name-driven, and pfSense barely uses attributes. No tool in this comparison caught it. |

`netgate-xlsx` scores a pass on the two HAProxy rows because it redacts by
element name regardless of content, which also removes the short references.
Whether that is better depends on whether you would rather lose the reference or
keep it.

To confirm the HAProxy rows are content-dependent rather than a blind spot:

```bash
printf '%s\n' \
  '<pfsense><installedpackages><p><config>' \
  '<ha_certificates>MIIDXTCCAkWgAwIBAgIJAKL0UG+mRkSPMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFV</ha_certificates>' \
  '</config></p></installedpackages></pfsense>' > /tmp/cert-probe.xml

pfsense-redactor /tmp/cert-probe.xml --stdout
# <ha_certificates>[REDACTED_CERT_OR_KEY]</ha_certificates>
```

## Reproducing this

```bash
pfsense-redactor tests/corpus/canary-corpus.xml --stdout --aggressive \
  | grep -oE 'CANARY_[A-Z0-9_]+' | sort -u
```

Every marker printed is one that survived. Expect exactly four:

```
CANARY_ATTR_PLAIN
CANARY_HAPROXYCERTS
CANARY_SSLOFFLOAD
CANARY_WGPUB
```

Run the same file through any other tool and count its survivors the same way.

## Keeping the number honest

`tests/integration/test_canary_corpus.py` pins this result in CI and fails in
both directions: a fifth marker surviving is a redaction regression, and one of
the four disappearing means this page is out of date. A published coverage
number that nothing enforces drifts, so it is enforced.

## Full results

<details>
<summary>All 46 planted secrets</summary>

| Path | Secret type | redactor 1.1.1 | ForesightCyber | netgate-xlsx |
| --- | --- | :--: | :--: | :--: |
| `user/bcrypt-hash` | password hash | ✅ | ✅ | ✅ |
| `user/md5-hash` | password hash | ✅ | ❌ | ❌ |
| `user/nt-hash` | password hash | ✅ | ❌ | ❌ |
| `user/authorizedkeys` | SSH keys | ✅ | ✅ | ✅ |
| `user/ipsecpsk` | per-user IPsec PSK | ✅ | ❌ | ❌ |
| `authserver/ldap_bindpw` | LDAP bind password | ✅ | ❌ | ❌ |
| `authserver/radius_secret` | RADIUS secret | ✅ | ❌ | ✅ |
| `zone/radiussecret` | captive portal RADIUS | ✅ | ❌ | ❌ |
| `snmpd/rocommunity` | SNMP community | ✅ | ✅ | ❌ |
| `snmpd/rwcommunity` | SNMP community | ✅ | ❌ | ❌ |
| `wpa/passphrase` | WPA PSK | ✅ | ❌ | ❌ |
| `phase1/pre-shared-key` | IPsec PSK | ✅ | ✅ | ✅ |
| `mobilekey/pre-shared-key` | IPsec mobile PSK | ✅ | ✅ | ✅ |
| `phase1/eap_password` | EAP credential | ✅ | ❌ | ❌ |
| `openvpn-client/tls` | TLS key | ✅ | ✅ | ✅ |
| `openvpn-client/auth_pass` | VPN password | ✅ | ✅ | ❌ |
| `openvpn-client/custom_options` | inline blob | ✅ | ❌ | ❌ |
| `item/privatekey` | WireGuard private key | ✅ | ✅ | ❌ |
| `item/presharedkey` | WireGuard PSK | ✅ | ❌ | ❌ |
| `item/publickey` | WireGuard public key (deny-listed) | ❌ | ✅ | ❌ |
| `ppp/password` | PPPoE | ✅ | ✅ | ✅ |
| `dyndns/password` | DynDNS | ✅ | ✅ | ✅ |
| `dyndns/updateurl` | token in query string | ✅ | ❌ | ❌ |
| `alias/url` | licence in query string | ✅ | ✅ | ❌ |
| `alias/detail` | credentials in free text | ✅ | ✅ | ❌ |
| `smtp/password` | SMTP | ✅ | ✅ | ✅ |
| `smtp/passwordagain` | SMTP duplicate field | ✅ | ❌ | ❌ |
| `telegram/api_key` | bot token | ✅ | ❌ | ❌ |
| `pushover/apikey` | API key | ✅ | ❌ | ❌ |
| `pushover/userkey` | user key | ✅ | ❌ | ❌ |
| `config/maxmind_key` | pfBlockerNG licence | ✅ | ✅ | ❌ |
| `item/accountkey` | ACME account key | ✅ | ❌ | ❌ |
| `a_dnsprovider/dns_cf_token` | Cloudflare token | ✅ | ❌ | ❌ |
| `config/ha_certificates` | HAProxy certs (see above) | ❌ | ❌ | ✅ |
| `config/ssloffloadcert` | HAProxy cert (see above) | ❌ | ❌ | ✅ |
| `config/influx_token` | InfluxDB token | ✅ | ❌ | ❌ |
| `config/token` | bare token | ✅ | ❌ | ❌ |
| `config/bearer_token` | bearer token | ✅ | ❌ | ❌ |
| `config/access_key` | S3 access key | ✅ | ❌ | ❌ |
| `config/secret_access_key` | S3 secret | ✅ | ❌ | ❌ |
| `config/tlspskvalue` | Zabbix PSK | ✅ | ❌ | ❌ |
| `config/upsd_users` | NUT password | ✅ | ✅ | ❌ |
| `config/userparams` | Zabbix script path | ✅ | ✅ | ❌ |
| `config/webhook_url` | Slack path token | ✅ | ❌ | ❌ |
| `config_note[@secret]` | attribute | ✅ | ❌ | ❌ |
| `config_note[@note]` | attribute free text | ❌ | ❌ | ❌ |
| **Total** | | **42 / 46** | **17 / 46** | **11 / 46** |

</details>
