# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0][] - 2026-07-28

Secret detection hardening. Five classes of credential that previously survived
redaction while the run reported success are now removed or reported.

### Security

- **Private-key PEM material is now redacted in every mode, whatever holds it.**
  A private key stored in an element or attribute whose name the tool did not
  recognise was previously *reported* as a retained high-entropy value and left
  in the output, and the run exited 0. A PEM private-key header is unambiguous
  evidence of key material and carries no over-redaction risk, so the
  report-only policy no longer applies to it. Recognised headers: `PRIVATE KEY`,
  `RSA`/`EC`/`DSA`/`ED25519 PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `OPENSSH
  PRIVATE KEY`, `SSH2 ENCRYPTED PRIVATE KEY`, `PGP PRIVATE KEY BLOCK` and
  OpenVPN's `STATIC KEY`. Public keys and certificates are unaffected.
  (FINDING-01, FINDING-02)

- **Base64 and Base64URL values are inspected for key material.** Packages that
  store credentials encoded — ACME account keys, several backup agents — hid the
  PEM header from every check the tool made. Values are now decoded to a bounded
  depth of 3 and re-examined, so single- and double-wrapped key material is
  found. Decoding is bounded in source length, decoded size, depth and total
  operations per value, and decoded content is never logged, sampled or placed
  in an error message. (FINDING-03)

- **JWTs are detected and redacted in every mode.** A compact token's `.`
  separators defeated the shape test, so a JWT was neither redacted nor
  reported. Recognised by the `eyJ` prefix or by the first segment decoding to a
  JOSE header; ordinary dotted strings — hostnames, versions, IPv4 addresses,
  filenames, reversed package names — are not affected. (FINDING-05)

- **Long single-character-class values are no longer invisible.** The opaque
  value test required two of {digit, upper, lower}, so an all-lowercase token,
  an all-uppercase token and a digest spelled only in `a-f` were neither
  redacted nor **reported** — `--fail-on-warn` could not see them and the
  summary never mentioned them. Hex values of 32 characters or more, and
  Base64-shaped values of 36 or more, are now judged on length and Shannon
  entropy instead. UUIDs, all-zero fields and padding are excluded by shape.
  (FINDING-04)

- **Element names and attribute names are classified by one shared predicate.**
  The two patterns disagreed: `bearer`, `cookie` and `signature` were secrets
  only as attributes; `credentials`, `privkey`, `licensekey`, `psk`,
  `passphrase` and `community` only as elements. The deny-list now applies to
  attribute names as it always has to element names. (FINDING-10)

- **13 further credential-bearing element names are recognised**: `pwd`,
  `bearer`, `salt`, `seed`, `otpseed`, `digest`, `hash`, `nonce`, `keydata`,
  `keystore`, `authorization`, `sessionid` and `totp`. (FINDING-09)

- **Element text and attribute values are classified by one shared function.**
  `unambiguous_secret_kind` decides what counts as private-key material or a
  JWT, and both paths dispatch on its answer, so the two cannot come to
  different conclusions about the same value. This is the parity the name
  patterns already have (FINDING-10), applied to values.

### Changed

- Values in these positions may now be redacted where they were previously kept
  and listed among the retained high-entropy paths. Nothing that was redacted
  before is kept now. If you relied on reading a retained value out of the
  output, it will be `[REDACTED_CERT_OR_KEY]` or `[REDACTED]` instead.

- `<digest>` and `<hash>` are decided by their value rather than their name, so
  `<digest>SHA384</digest>` — IPsec selecting an algorithm — is preserved while
  anything outside a closed list of algorithm names in those elements is
  redacted. Algorithm-selector names (`hash-algorithm`, `hashalgo`,
  `digestalgo`, `saltlen` and similar) and the OpenVPN `auth-retry*` directives
  are on the deny-list.

- The retained-value warning is correspondingly shorter, and the count that
  `--fail-on-warn` reads no longer includes private keys or JWTs, because those
  are no longer retained.

No action is required. No CLI option, default or exit code changes in this
release, and output remains valid pfSense XML.

## [1.2.0][] - 2026-07-28

Three changes to how coverage is decided and measured. Two close gaps the canary
corpus had been reporting since it was published; the third replaces the
benchmark's written admission of bias with a measurement of it.

Against the 46-secret canary corpus, `--aggressive` now catches 44 where 1.1.2
caught 42, and 45 with `--redact-descriptions` where 1.1.2 caught 43.

### Security
- **FIX**: A bracketed IPv6 address carrying a zone identifier was not redacted
  at all. `%` was a token separator, so `[2001:db8::1%igb0]:51820` split into
  `[2001:db8::1` and `igb0]:51820`; the first half carried an unbalanced
  bracket, failed to parse as an address, and was returned untouched.

  The bare form `fe80::1%igb0` appeared to work, but only by accident: its two
  halves were masked and copied through separately. Every bracketed form leaked,
  with or without a port, and **routable addresses leaked as readily as
  link-local ones**. `[address%zone]:port` is the shape pfSense writes for a
  WireGuard peer endpoint, so real configs carry it.

  `%` is now a token character. The masking code already handled the shape
  correctly once given the whole token; only tokenising was wrong.

  Two existing tests covered this exact input and passed throughout, because
  they asserted only that the zone identifier and the port survived. Returning
  the input untouched satisfies both. They now assert the address is gone as
  well, which is the property that actually mattered.

- **FIX**: A short value in a certificate-named element was kept on the strength
  of its length alone. Under 50 characters and without a PEM header, it was
  assumed to be a `refid` reference rather than key material.

  References are worth keeping: they are not secret, and they let a reader
  follow the structure of the config. But length is a proxy for meaning, so
  anything short enough was kept whatever it actually was. `<ha_certificates>`
  and `<ssloffloadcert>` were the two canary markers this let through.

  The config already declares which references exist. Every `<refid>` in the
  file is now collected before redaction starts, and a short value in a
  certificate-named element is kept only if it resolves against that list.
  Values resolving to nothing are redacted as secrets. Where a value carries
  several references, as HAProxy's can, all of them must resolve: a partial
  match means the value is not purely a reference list.

  A config declaring no `<refid>` at all therefore loses its short certificate
  values. That is deliberate, and follows the threat model: absent evidence that
  a value is a reference, treat it as a secret.

  Elements that hold certificate material directly (`<crt>`, `<cert>`,
  `<public-key>`) are untouched by this. A short value in one of those is a
  truncated key, not a reference, so resolving it would answer the wrong
  question.

- **FIX**: `--fail-on-warn` could not see key material in an XML attribute.
  `SENSITIVE_ATTR_PATTERN` matches an attribute's *name*, so a blob sitting in
  an attribute named something unremarkable was neither redacted nor counted
  among the retained high-entropy values the gate reads. A CI check passed on a
  file whose own output had never mentioned it.

  Attribute values are now entropy-checked the same way element values have
  been: reported for review by default, with the attribute named in the path
  (`telemetry[@endpoint_id]`), and redacted under `--aggressive`.

  Reported rather than redacted by default because no pfSense config examined in
  testing uses XML attributes at all. This covers third-party packages rather
  than an observed leak, and rewriting values by default on that evidence would
  over-redact for everyone.

  This does **not** close the `config_note[@note]` canary, and is not meant to.
  That marker is prose, and the entropy heuristic requires 32 or more characters
  with no spaces. `--redact-descriptions` is what covers it, as it has since
  1.1.2.

### Changed
- Redacting an already-redacted file is now a no-op for certificate elements.
  Without the placeholder check added here, `[REDACTED_CERT_OR_KEY]` failed to
  resolve as a reference on a second pass and degraded to the less informative
  `[REDACTED]`.

### Documentation
- `docs/benchmark.md` now reports where the corpus came from as a measurement
  rather than a caveat. Every released version was re-run against it to find
  which release first caught each marker: 15 were already caught by 1.0.10, 26
  document a gap 1.1.0 closed, and one each for 1.1.1 and 1.1.2. **31 of 46
  markers, 67%, were planted against ground the tool did not yet hold, and none
  of the 46 came from outside this project.** That second number is the honest
  limit of the benchmark, and it is now stated as a number rather than a
  disclaimer.
- `tests/corpus/canary-corpus.xml` is frozen at 46 markers, enforced by test. It
  is the file the two comparison tools were scored against, and that table stops
  meaning anything the moment its denominator moves.
- New `tests/corpus/canary-corpus-supplementary.xml` for markers added since,
  scored separately and with no known survivors. Contributed markers go here.

## [1.1.2][] - 2026-07-28

### Security
- **FIX**: Webhook tokens survived in default mode unless the element happened
  to be named for a secret. 1.1.0 fixed `<webhook_url>` by matching the element
  *name*, so a Slack URL in `<slack_url>`, `<notifyurl>` or a plain `<url>` kept
  its token. The token is the whole authorisation, since anyone holding the
  URL can post as that integration.

  Path-segment redaction stays gated behind `--aggressive` in general, because
  pfBlockerNG feed URLs legitimately carry long path components that redaction
  would destroy. The gate is now lifted for endpoints where the path token is
  unambiguously a credential: `hooks.slack.com/services/`,
  `discord.com/api/webhooks/` (and the `discordapp.com`, `ptb.` and `canary.`
  variants), and `api.telegram.org/bot`.

  Hosts are matched exactly, never by suffix, so `hooks.slack.com.example.net`
  does not inherit the rule. A non-webhook path on a webhook host, such as a
  `discord.com/channels/…` link, is unaffected, as are feed URLs on any other
  host.

  Found by scanning redacted output with gitleaks: of six realistic secrets in a
  test config it flagged exactly one, and this was it. Running an independent
  scanner over the output catches what a name-driven redactor cannot.
- **FIX**: `--fail-on-warn` covered the root-tag check and nothing else, so a
  config carrying a value the tool declined to redact printed "Review before
  sharing" and still exited 0. An automated check passed on a file its own
  output said to look at, and `docs/use-cases.md` recommends the flag for
  exactly that job.

  It now also fails when high-entropy values are retained, under `--dry-run`
  as well, since checking without writing is the natural shape for CI and it was
  the one mode that could not report a problem. The message names the count
  and points at `--aggressive`. Redacted output is still written when the gate
  fails, since the retained values were reported rather than leaked and the
  operator needs the file to review them.
- **ADD**: Microsoft Teams webhook endpoints are recognised, so their path
  tokens are redacted in every mode alongside Slack, Discord and Telegram.
  Teams puts the tenant in a subdomain, so `*.webhook.office.com` is matched as
  a suffix, including the leading dot, which is what stops
  `notwebhook.office.com` qualifying. Suffix matching is the looser rule, so it
  applies only to domains listed for it rather than to the whole set. The
  legacy `outlook.office.com` connector stays an exact match.

  Self-hosted tools such as Mattermost are deliberately absent: their webhooks
  sit at `/hooks/<token>` on whatever host the operator chose, so there is no
  host to match, and treating every `/hooks/` path as a credential would redact
  ordinary paths on unrelated servers. Those still need `--aggressive`.

### Added
- `--redact-descriptions` now covers free-text **attributes** as well as
  elements: `note`, `comment`, `label`, `title` and similar. Attributes named
  for a secret were already redacted; these are the ones whose name says
  nothing about the contents, where a PIN or a circuit reference ends up inside
  a sentence and no pattern reliably finds it.

  This closes the last genuine miss in the canary corpus, taking it from 42/46
  to **43/46**. The remaining three are two corpus artefacts and one deliberate
  choice. Structural attributes are untouched: redacting `version` or
  `interface` would break the reader's ability to follow the config.

## [1.1.1][] - 2026-07-28

Follow-up to 1.1.0, in two parts. The first came from a second canary-corpus
report. 1.1.0 caught 41 of 46 planted secrets where 1.0.10 caught 15, and this
closes the remaining URL path gaps plus an over-redaction bug found while
confirming them. The second is two long-standing defects surfaced while
reviewing that work, both older than 1.1.0.

### Security
- **FIX**: Three credential formats bypassed URL path-segment detection:
  - **AWS access key IDs** (`AKIA...`) are exactly 20 characters, and the
    length test was `<= 20`, so the entire format was excluded by an
    off-by-one.
  - **Telegram bot tokens** are `bot<id>:<secret>`, and the colon failed the
    base64 character test, so a 47-character credential was treated as an
    ordinary path segment. Segments are now split on `:` before testing.
  - **Tokens without digits** were never flagged. The digit requirement exists
    to protect underscore-joined route names such as `Open_VM_Tools_package`,
    and is now applied only below 24 characters.
- **FIX**: `<webhook_url>` and similar elements are now redacted whole. A Slack
  or Discord webhook URL is a credential in its entirety, not merely a
  secret-bearing path segment.
- **HARDENING**: Input declaring a `<!DOCTYPE>` is now refused. pfSense never
  emits one, so its presence means the file did not come from pfSense
  untouched.

  This is deliberately *not* described as an XXE fix. `xml.etree.ElementTree`
  does not resolve external entities. A `SYSTEM` entity raises `ParseError`,
  so there is no file disclosure and no SSRF. What it does do is expand
  *internal* entities, where a few hundred bytes of nested definitions expand
  to gigabytes. Severity is low: the input is a file the user supplies, and the
  failure is loud rather than a silent under-redaction.

  The whole prolog is scanned rather than a fixed-size prefix. A DOCTYPE placed
  behind a larger comment passes a prefix check untouched, which would leave
  the guard reporting success while doing nothing.

### Fixed
- **FIX**: FQDN substitution rewrote filenames as domains, corrupting output
  rather than redacting it. `list.txt`, `emerging-block.rules`,
  `pfblockerng.php` and `haproxy.sh` all became `example.com`.

  This affected **default mode**, not only `--aggressive`: `<url>` is a known
  URL-bearing element, so pfBlockerNG feed URLs were corrupted without any
  opt-in. It was also present in this project's own reference snapshots.

  URLs are now protected from the FQDN pass, which has already masked their
  hosts, and bare filenames are recognised by extension or by filesystem-path
  context. Context is required because extension alone cannot decide it: `.sh`,
  `.pl`, `.io` and `.zip` are all real TLDs, so `haproxy.sh` is preserved
  inside a path but still redacted in prose.
- **FIX** (predates 1.1.0): IPv6 anonymisation produced invalid addresses once
  the RFC 3849 pool was exhausted. The RFC 4193 overflow mapping used
  `((overflow - 1) % 0x10000) + 1`, which ranges `1..0x10000`, one past what a
  hextet can hold, so every 65536th counter emitted a five-digit group such as
  `fd00::0:10000`, which is not parseable. It now rolls into the upper hextet
  (`fd00::1:0`), which is what the implementation comment always described.
  Reachable only with 131,071 or more unique IPv6 addresses in one config.

  Two existing tests asserted the malformed value, complete with comments
  working through the arithmetic that produced it, which is why the defect
  survived. Both are corrected.
- **FIX** (predates 1.1.0): The sensitive-directory check used a plain string
  prefix, so paths that merely *begin* with a protected directory's name were
  rejected: `/rootkit`, `/roots`, `/var/logs-archive`, `/bootstrap`,
  `/usr/binaries`, `/libraries` and `/runner` were all refused as output
  locations. Matching is now component-aware, and no longer depends on whether
  an entry was written with a trailing separator. This over-blocked rather than
  under-blocked, so it was a usability failure rather than a security one, and
  every protected directory remains blocked.

- **FIX** (predates 1.1.0): Windows system directories were hardcoded to `C:`,
  so a machine with Windows installed on any other drive had no write
  protection for its system directories at all. `D:\\Windows\\System32` was
  freely writable. The real locations are now read from `SystemRoot`, `windir`,
  `ProgramFiles`, `ProgramFiles(x86)`, `ProgramW6432` and `ProgramData`, the
  same way temp directories are already read from `TMPDIR`/`TEMP`. The `C:`
  literals are kept, since the full set is applied on every platform by design.
  No effect off Windows, where none of these variables are set.

### Known limitations
- A path segment of 21-23 characters containing no digit is not detected.
  `Open_VM_Tools_package` (a route name that must be preserved) and a
  hypothetical 21-character alphabetic token are the same length and shape, so
  no length threshold separates them. Real Slack and Discord tokens are 24+
  characters and are detected.

## [1.1.0][] - 2026-07-27

### Security
- **FIX**: Secret detection matched element names exactly, so the concatenated spellings pfSense
  and its packages actually emit were never redacted. `REDACT_ELEMENTS` contained `community`,
  but pfSense writes `<rocommunity>`/`<rwcommunity>`; the entry that existed was the one that
  never fired. Against a 46-secret canary corpus, 31 secrets (67%) survived in **every** mode.
  Newly redacted element names include:
  - SNMP: `rocommunity`, `rwcommunity`
  - Wireless: `passphrase` (WPA/WPA2 PSK)
  - VPN: `auth_pass`, `presharedkey` (WireGuard), `ipsecpsk`, `eap_password`
  - Auth: `radiussecret`, `authorizedkeys`
  - Packages: `accountkey` (ACME), `dns_cf_token`, `maxmind_key` (pfBlockerNG),
    `influx_token` (Telegraf), `tlspskvalue` (Zabbix), `access_key`/`secret_access_key` (S3),
    `userkey` (Pushover), `ha_certificates`/`ssloffloadcert` (HAProxy)

  This also affected this project's own sample configs, where `passwordagain`, `crypto_password`,
  `redis_password`, `auth_pass` and `rocommunity` values were all being emitted in the clear.
- **FIX**: `_get_tag_base()` stripped trailing digits but was only applied to IP-bearing elements,
  so `password` was redacted while `password2` and `passwordagain` were not. It is now applied to
  secret and certificate matching as well.
- **FIX**: Credentials embedded in URL query strings were preserved while the hostname was
  anonymised, giving false reassurance that a URL had been sanitised. Query-parameter values whose
  parameter name denotes a secret (`token`, `key`, `password`, `license`, …) are now redacted by
  default. Under `--aggressive`, credential-shaped URL path segments (Slack/Discord webhook
  tokens) are redacted too.
- **FIX**: Free-text option blocks (`custom_options`, `upsd_users`, `userparams`, `advanced`, …)
  were never scanned. `custom_options` is the standard place for OpenVPN directives and commonly
  holds `askpass` and `auth-user-pass`. These are now scanned for inline `key=value` credentials
  and secret-bearing directives, and redacted wholesale under `--aggressive`.
- **FIX**: The PEM/base64 blob heuristic was gated on the tag being exactly `key`, so identical
  content in any other element passed through untouched.
- **FIX**: URL credentials (`user:password@host`) were preserved in elements that are not known
  URL carriers, so a URL could be emitted with its query secret shown as `[REDACTED]` while the
  HTTP-basic password beside it survived in full, producing output that reads
  as sanitised when it is not.
  Userinfo redaction now follows the same policy on every URL path, and a URL carrying credentials
  is rewritten even when nothing else in it changes.
- **FIX**: Free-text blob elements received *less* URL scanning than unrecognised elements, because
  they reported their text as handled. They are now scanned for URL secrets as well as inline
  `key=value` credentials, and the key=value scanner no longer mistakes a URL scheme for a key.
- **FIX**: `--dry-run-verbose` printed URL credentials to the console. The sample display masked the
  host and the userinfo password but passed the path and query through verbatim, so a preview of
  `https://api.example.com/v1?token=...` showed the token in full: in the
  terminal, and from there
  in CI logs or a pasted ticket. This is the flag users run precisely to check what will happen
  before sharing, so it now redacts path and query secrets too.

### Added
- **NEW**: `--redact-descriptions` flag to redact free-text descriptions and identifiers
  (`descr`, `detail`, `hostname`, `ssid`). DHCP static-map descriptions are a reliable source of
  personal names. Off by default, as these fields aid troubleshooting.
- Unrecognised high-entropy values are now reported in the summary with their element path, so
  retained secrets can be reviewed manually. Previously the summary only counted what *was*
  redacted, making retained values impossible to audit. `--aggressive` redacts them outright.

### Changed
- **BREAKING (output)**: Secret element matching is now pattern-based rather than exact-match, so
  more fields are redacted by default. A deny-list keeps known non-secrets readable
  (`snortcommunityrules`, `pass_order`, `password_type`, `source_hash_key`, `certref`, `keylen`).
  Validated at zero false positives across all 875 unique element names in the sample configs.
- `--aggressive` now broadens *secret* detection, not just IP/domain rewriting. Previously it
  changed none of the 31 leaked canaries, despite users reasonably reading it as "redact more
  secrets".
- Certificate-shaped elements are redacted only when their content looks like PEM or a long blob,
  so short certificate *references* stay readable.

## [1.0.10][] - 2025-12-15

### Changed
- Improved PyPI metadata with additional classifiers
- Added code quality tool configurations (Black, isort, mypy)
- Enhanced project URLs (Bug Tracker, Changelog, Source Code)
- Updated test snapshots for new version

## [1.0.9][] - 2025-11-08

### Added
- **NEW**: Version checking functionality with `--version` and `--check-version` flags
  - `--version`: Display current version and exit (instant, no network call)
  - `--check-version`: Check PyPI for latest version with context-aware upgrade instructions
  - Automatic installation method detection (pipx, venv, user, source, pip)

## [1.0.8][] - 2025-11-05

### Security
- **FIX**: Added symlink security check for `--inplace` mode
  - Prevents following symlinks when using `--inplace` to avoid overwriting sensitive system files
  - Symlink check now occurs before file size validation to handle directory symlinks on Windows
  - Detects symlinks to regular files, directories, and broken symlinks
  - Shows symlink target in error message to help users understand the issue
  - Hardlinks continue to work (they're safe, unlike symlinks)
  - Added 10 tests in `tests/unit/test_symlink_security.py`
  - Prevents attack scenario: attacker replaces config.xml with `ln -s /etc/passwd config.xml`
- **FIX**: Invalid ports in URLs are now omitted to prevent malformed output
  - Previously, invalid ports (out of range, zero, negative, non-numeric) were appended without validation
  - Now omits invalid ports entirely, ensuring output URLs are always valid and parseable
  - Added debug logging when invalid ports are detected in URL netloc
  - Prevents malformed URLs that could bypass downstream filtering or cause parsing errors
  - Added 18 tests in `TestURLInvalidPortHandling`
- **FIX**: Enhanced whitespace validation in domain normalisation
  - Previously only checked for space character `' '`, allowing tabs, newlines, and other whitespace to bypass validation
  - Now uses regex `\s` to reject ANY whitespace character (space, tab, newline, carriage return, non-breaking space, etc.)
  - Prevents malformed domains like `"evil.com\texample.com"` from passing validation
  - Prevents potential bypass of suffix matching logic and allowlist validation
  - Updated comment to clarify "any whitespace" instead of "internal whitespace"
  - Added 9 tests covering all whitespace types in `TestDomainNormalisationSecurity`
- **FIX**: Added port range validation (1-65535) for IP addresses
  - Previously accepted invalid ports (0, greater than 65535) which could cause confusion or security issues
  - Port 0 (reserved) is now rejected and not stripped from IP addresses
  - Ports greater than 65535 are now rejected and not stripped from IP addresses
  - Leading zeros in port numbers are normalised (e.g., `:00080` becomes `:80`)
  - Validation applies to both `IPv4:port` and `[IPv6]:port` formats
  - Invalid ports in URLs are handled gracefully without crashes
  - Added 27 tests in `tests/unit/test_port_validation.py`

### Fixed
- **FIX**: Prevent re-redaction of RFC documentation IPs in anonymisation mode
  - RFC 5737 IPv4 ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) now recognised as masked values
  - RFC 3849 IPv6 range (2001:db8::/32) now recognised as masked values
  - Prevents re-redaction on subsequent runs, ensuring idempotent behaviour
  - Prevents mapping instability and statistics inflation
  - Only applies in `--anonymise` mode to avoid interfering with normal redaction
  - Defence-in-depth implementation across `_is_already_masked_host()`, `_mask_ip_like_tokens()`, `_normalise_masked_url()`, and `_anonymise_ip_for_url()`
- **FIX**: Fixed IP counter overflow in anonymisation mode
  - After 762 unique IPs, counter would wrap and create duplicate mappings (IP #763 → 192.0.2.1, same as IP #1)
  - Now falls back to RFC 1918 private range (10.0.0.0/8) for overflow addresses
  - Supports up to 16,777,978 unique IPv4 addresses (762 RFC 5737 + 16,777,216 RFC 1918)
  - IPv6 overflow (after 65535 addresses) falls back to RFC 4193 ULA range (fd00::/8)
  - Added warning logs at thresholds: 700, 750, 762 addresses used
  - Added warning on first overflow with explanation of fallback behaviour
  - Added 18 tests in `tests/unit/test_ip_overflow.py`
  - Verified no duplicate mappings occur across RFC and overflow ranges

### Security
- **FIX**: Added file path validation to prevent arbitrary file read/write operations
  - Blocks directory traversal attempts (`../../../etc/passwd`)
  - Blocks paths with null bytes (path traversal attack vector)
  - Blocks writing to sensitive system directories (`/etc`, `/sys`, `/proc`, `/Windows/System32`, etc.)
  - Blocks writing to critical system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, etc.)
  - Validates paths before any file operations (input, output, and in-place modes)
  - Resolves symbolic links to detect attempts to write to protected locations
  - By default, only allows relative paths and absolute paths to safe locations (home, CWD, temp directories)

### Added
- New `--allow-absolute-paths` flag to explicitly enable absolute path usage
  - Required for absolute paths outside safe locations (home, CWD, temp)
  - Still enforces protection against sensitive system directories
  - Useful for intentional absolute path operations
- New path validation functions:
  - `validate_file_path()`: Path security validation
  - `_get_sensitive_directories()`: Computes list of protected system directories
- 45 comprehensive tests for path validation:
  - 28 unit tests in `tests/unit/test_path_validation.py`
  - 17 integration tests in `tests/integration/test_path_security.py`
  - Tests cover directory traversal, null bytes, sensitive directories, symbolic links, and edge cases

### Changed
- Path validation now occurs before file existence checks
- In-place mode (`--inplace`) now validates paths with stricter output-level checks
- Dry-run mode now validates output paths for security (even though no write occurs)
- Error messages now clearly indicate when `--allow-absolute-paths` is required

## [1.0.7][] - 2025-11-03

### Fixed
- **CRITICAL FIX**: Fixed whitespace corruption in URL/email/FQDN redaction
  - `_redact_urls_safe`, `_redact_emails_safe`, and `_redact_fqdns_safe` were using `text.split()` and `' '.join()`
  - This collapsed all whitespace (including newlines) into single spaces, corrupting XML text content
  - Now uses `re.sub()` with callbacks to preserve original whitespace structure
  - Maintains ReDoS protection via length pre-filtering in the callback functions
- **CRITICAL FIX**: Fixed whitespace domain handling vulnerability in allowlist validation
  - Added `.strip()` to prevent allowlist bypass with whitespace-only domains (e.g., `"   "`)
  - Whitespace-only domains could previously match ANY domain in suffix matching
  - Added validation to reject domains with internal whitespace
  - Added 6 comprehensive tests in `TestDomainNormalisationSecurity`
- **MEDIUM FIX**: Fixed port stripping logic to validate IPv4 addresses
  - Now validates IP addresses using `ipaddress.ip_address()` before stripping ports
  - Prevents incorrect port stripping from non-IP tokens like `foo.bar.baz:8080`
  - Previously only checked for presence of dots, not valid IP format
  - Added 4 tests in `TestPortStrippingSecurity`
- **MEDIUM FIX**: Fixed overly broad sensitive attribute matching
  - Replaced substring matching with anchored regex patterns using word boundaries (`\b`)
  - Previously `'pass'` matched `compass_heading`, `'auth'` matched `author`, etc.
  - Now uses precise pattern: `\b(?:password|passwd|pass|key|secret|...)\b`
  - Prevents false positives whilst maintaining security for genuine sensitive attributes
  - Added 16 comprehensive tests in `TestSensitiveAttributeAnchoring`
- **ENHANCEMENT**: Prevent re-anonymisation of already-masked domains
  - `_is_already_masked_host()` now recognises `domain\d+\.example` pattern when `--anonymise` is enabled
  - Already-masked domains like `domain7.example` are no longer re-anonymised during processing
  - Ensures consistent handling of previously redacted configurations

### Added
- New `--quiet` / `-q` flag: Suppress progress messages (show only warnings and errors)
- New `--verbose` / `-v` flag: Show detailed debug information
- Flags are mutually exclusive and validated at runtime
- `ColouredFormatter` class for optional ANSI colour output
- `setup_logging()` function for configuring log levels and output streams
- New `--redact-url-usernames` CLI flag for enhanced URL credential redaction
  - Allows redacting sensitive usernames (e.g., `admin`, `root`) in URLs
  - Default behaviour: preserve usernames, always redact passwords (`ftp://user:REDACTED@host`)
  - With flag: redact both (`ftp://REDACTED:REDACTED@host`)
  - Added 7 tests in `TestURLUsernameRedaction`

### Changed
- **BREAKING**: Replaced `print()` statements with Python's `logging` module for better integration
  - All output now uses proper log levels (ERROR, WARNING, INFO, DEBUG)
  - Logs route to stdout by default, stderr when using `--stdout` mode
  - Removed `--stats-stderr` flag (no longer needed - logging handles routing automatically)
- Coloured log output when outputting to a TTY (auto-detected, disabled for pipes/redirects)
  - ERROR: Red, WARNING: Yellow, INFO: Green, DEBUG: Cyan
- Domain normalisation now strips whitespace before processing dots
- Port stripping now requires valid IPv4 address validation
- URL/email/FQDN redaction now uses `re.sub()` instead of tokenisation to preserve whitespace
- **IMPROVEMENT**: Simplified IPv6 documentation address mapping
  - `_counter_to_rfc_ip()` now uses cleaner wrapping logic: `h = (counter - 1) % 0xFFFF + 1`
  - Maps counters to single hextet (1..65535) with wrapping: `2001:db8::1` through `2001:db8::ffff`
  - More predictable and maintainable than previous two-hextet approach

### Removed
- `--stats-stderr` flag (replaced by automatic log routing in `--stdout` mode)

## [1.0.6][] - 2025-11-02

### Security
- **CRITICAL FIX**: Extended URL regex to handle non-HTTP protocols (FTP, FTPS, SFTP, SSH, Telnet, File, SMB, NFS)
  - Previously only HTTP/HTTPS URLs were matched, allowing credentials in `ftp://user:pass@host` URLs to bypass redaction
  - Credentials in non-HTTP URLs would have leaked through the bare FQDN redaction path
  - All protocol URLs now properly redact passwords whilst preserving usernames and structure
- **CRITICAL FIX**: URLs without hostnames (e.g., `file:///path`) are now preserved unchanged
  - Previously `file:///path` would be incorrectly transformed to `file://example.com/path`
  - This changed URL semantics from local filesystem to network file share
  - Added early return in `_mask_url()` when `hostname` is `None` or empty
- **ENHANCEMENT**: Expanded email regex to support RFC 5322 special characters
  - Now matches emails with `!#$&'*/=?^`{|}~` in local part (e.g., `user!test@example.com`)
  - Maintains ReDoS protection with limited repetitions
  - Previous regex only matched `[A-Za-z0-9._%+-]`, missing many legal email addresses

### Added
- Module-level exports control via `__all__` (PfSenseRedactor, main, parse_allowlist_file)
- Python 3.9+ version check at module import time with clear error message
- Cached IDNA encoding using `@functools.lru_cache(maxsize=256)` for improved performance
- Type hint for maskers dictionary: `dict[str, Callable[[str], str]]`
- XML comment in output files: `<!-- Redacted using pfsense-redactor v1.0.6 -->`
- 14 comprehensive tests for URL handling:
  - 8 tests for non-HTTP protocol URL redaction
  - 6 tests for hostnameless URL preservation

### Changed
- Updated version to 1.0.6 in both `__init__.py` and `pyproject.toml`
- Updated all test reference files to include redaction comment


## [1.0.5][] - 2025-11-02

### Changed
- Updated installation documentation in README to address `externally-managed-environment` error
- Added installation alternatives for macOS and modern Linux distributions:
  - pipx installation (recommended for CLI tools)
  - Virtual environment setup
  - User space installation
- Improved source installation instructions with separate options for development and virtual environment setups

## [1.0.4][] - 2025-11-02

### Changed
- Upgraded minimum Python version from 3.8 to 3.9
- Modernised type hints using `from __future__ import annotations` and PEP 604 union syntax (`X | Y`)
- Replaced all `typing` module imports with built-in types (`list`, `dict`, `tuple`, etc.)
- Refactored code to eliminate pylint warnings and improve maintainability
- Removed `ET.indent()` try/except block (now available in Python 3.9+)

### Added
- Linter configurations:
  - `.pylintrc` for production code (strict)
  - `.pylintrc-tests` for test code (relaxed)
  - `.bandit` for security linting

### Fixed
- Consistent XML indentation across Python versions
- All pylint, Prospector, and Bandit warnings resolved
- CI/CD workflows updated to test Python 3.9-3.13

## [1.0.3][] - 2025-11-02

### Added
- Initial PyPI release
- Python package structure with proper packaging configuration
- Command-line tool `pfsense-redactor` installable via pip
- Comprehensive redaction of sensitive pfSense configuration data:
  - Passwords, pre-shared keys, and API tokens
  - TLS/OpenVPN certificates and private keys
  - SNMP community strings and RADIUS secrets
  - Public IP addresses (with optional private IP preservation)
  - Domain names and email addresses
  - MAC addresses
  - URLs (with structure preservation)
- Multiple operational modes:
  - Default mode: Safe redaction for sharing
  - `--keep-private-ips`: Preserve RFC1918/ULA addresses
  - `--anonymise`: Consistent placeholder mapping for topology analysis
  - `--aggressive`: Comprehensive scrubbing of all fields
- Allow-list support for preserving known public services:
  - IP addresses and CIDR ranges
  - Domain names with suffix matching
  - IDNA/punycode support for internationalised domains
  - Default allow-list files (`.pfsense-allowlist`)
- Dry-run modes:
  - `--dry-run`: Statistics preview
  - `--dry-run-verbose`: Statistics with safely masked samples
- Smart handling of pfSense-specific structures:
  - XML namespaces
  - VPN configurations (IPSec, OpenVPN, WireGuard)
  - IPv6 zone identifiers
  - Firewall rules and gateway configurations
- Comprehensive test suite:
  - Unit tests for core functionality
  - Integration tests for CLI behaviour
  - Property-based tests for invariants
  - Reference snapshot tests
- Documentation:
  - Detailed README with usage examples
  - Publishing guide for maintainers
  - MIT licence

### Technical Details
- Python 3.8+ support
- Zero external dependencies (uses only standard library)
- Format-preserving redaction where possible
- Topology-aware anonymisation with consistent aliases
- Security-first design with comprehensive pattern matching

### Installation
```bash
pip install pfsense-redactor
```

### Usage
```bash
# Basic usage
pfsense-redactor config.xml

# Preserve private IPs (recommended for support/AI analysis)
pfsense-redactor config.xml --keep-private-ips

# Anonymise with consistent placeholders
pfsense-redactor config.xml --anonymise

# Preview changes without modifying files
pfsense-redactor config.xml --dry-run-verbose
```

[1.3.0]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.3.0
[1.2.0]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.2.0
[1.1.2]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.1.2
[1.1.1]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.1.1
[1.1.0]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.1.0
[1.0.10]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.0.10
[1.0.9]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.0.9
[1.0.8]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.0.8
[1.0.7]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.0.7
[1.0.6]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.0.6
[1.0.5]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.0.5
[1.0.4]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.0.4
[1.0.3]: https://github.com/grounzero/pfsense-redactor/releases/tag/1.0.3
