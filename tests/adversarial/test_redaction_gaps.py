"""Phase 2/3: redaction completeness and privacy leakage

Every test here asserts the property that should hold. Tests carrying
``xfail(strict=True)`` document a confirmed gap; the rest are regression pins
for behaviour that already works and must keep working.

All canaries are synthetic. The "PEM" bodies are base64-legal runs of the word
CANARY and decode to nothing.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from pfsense_redactor.redactor import (
    SECRET_TAG_PATTERN,
    SENSITIVE_ATTR_PATTERN,
    SECRET_TAG_DENYLIST,
    PfSenseRedactor,
)

from .decode_scan import find_key_material, find_markers

CANARY_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "CANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIV0123\n"
    "CANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIV4567\n"
    "-----END RSA PRIVATE KEY-----"
)


def redact(xml: str, **kwargs) -> str:
    """Run a full redaction over `xml` and return the serialised result

    Mirrors what redact_config does around the traversal - refid collection in
    particular - so tests exercise the same code path the CLI does.
    """
    redactor = PfSenseRedactor(**kwargs)
    root = ET.fromstring(xml)
    redactor.known_refids = redactor._collect_refids(root)  # pylint: disable=protected-access
    redactor.redact_element(root)
    return ET.tostring(root, encoding='unicode')


def wrap(inner: str) -> str:
    """Put `inner` inside a minimal but realistic package config"""
    return f"<pfsense><installedpackages><vendorpkg><config>{inner}</config></vendorpkg></installedpackages></pfsense>"


# ==========================================================================
# Key material in places the name patterns do not reach
# ==========================================================================
class TestKeyMaterialSurvival:
    """A private key must not survive, whatever element or attribute holds it"""

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-01: a PEM private key in an unrecognised element is "
               "reported as high-entropy but retained in default mode",
    )
    def test_pem_in_unknown_element_is_redacted(self):
        """Key material must not depend on the element being recognised"""
        out = redact(wrap(f"<vendorblob>{CANARY_PEM}</vendorblob>"))
        assert "BEGIN RSA PRIVATE KEY" not in out
        assert "CANARYPRIVATEKEY" not in out

    def test_pem_in_unknown_element_is_redacted_under_aggressive(self):
        """The documented escape hatch must actually work"""
        out = redact(wrap(f"<vendorblob>{CANARY_PEM}</vendorblob>"), aggressive=True)
        assert "BEGIN RSA PRIVATE KEY" not in out

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-02: a PEM private key in an attribute whose name is not "
               "matched by SENSITIVE_ATTR_PATTERN is reported but retained",
    )
    def test_pem_in_attribute_is_redacted(self):
        """Nor on the attribute name being recognised"""
        out = redact(wrap(f'<endpoint privkey="{CANARY_PEM}"/>'))
        assert "BEGIN RSA PRIVATE KEY" not in out

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-03: no decoding layer - base64-wrapped key material is "
               "never decoded, so the PEM marker is never seen",
    )
    def test_base64_wrapped_pem_is_redacted(self):
        """One layer of encoding must not conceal a key"""
        import base64  # pylint: disable=import-outside-toplevel
        encoded = base64.b64encode(CANARY_PEM.encode()).decode()
        out = redact(wrap(f"<payload>{encoded}</payload>"))
        assert not find_key_material(out), "key material recoverable by decoding"

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-03: double-base64-wrapped key material is not decoded",
    )
    def test_double_base64_wrapped_pem_is_redacted(self):
        """Nor two"""
        import base64  # pylint: disable=import-outside-toplevel
        once = base64.b64encode(CANARY_PEM.encode()).decode()
        twice = base64.b64encode(once.encode()).decode()
        out = redact(wrap(f"<blob>{twice}</blob>"))
        assert not find_key_material(out), "key material recoverable by decoding twice"


# ==========================================================================
# The entropy detector's blind spots
# ==========================================================================
class TestEntropyDetectorBlindSpots:
    """A value the detector cannot see is neither redacted nor reported

    Being reported is the weaker of the two outcomes, so these tests assert
    only that - if the tool notices at all, --fail-on-warn and the summary can
    do their job.
    """

    @staticmethod
    def _noticed(value: str) -> bool:
        """Whether the tool either redacted or at least reported the value"""
        redactor = PfSenseRedactor()
        root = ET.fromstring(wrap(f"<opaque>{value}</opaque>"))
        redactor.redact_element(root)
        return bool(redactor.stats['high_entropy_retained']) or '[REDACTED' in ET.tostring(
            root, encoding='unicode'
        )

    def test_mixed_class_base64_blob_is_noticed(self):
        """The case that works today - the control for the three below"""
        assert self._noticed("aGVsbG8gd29ybGQxMjM0NTY3ODkwQUJDREVGRw==")

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-04: _has_mixed_character_classes requires two of "
               "digit/upper/lower, so an all-lowercase blob is invisible",
    )
    def test_lowercase_only_blob_is_noticed(self):
        """Character-class uniformity must not confer invisibility"""
        assert self._noticed("canaryadvlowercaseonlysecretvaluehere")

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-04: an all-uppercase blob is invisible for the same reason",
    )
    def test_uppercase_only_blob_is_noticed(self):
        """The same, in the other direction"""
        assert self._noticed("CANARYADVUPPERCASEONLYSECRETVALUEHERE")

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-04: the hex branch requires a digit, so a hex secret "
               "made only of a-f is invisible",
    )
    def test_digitless_hex_blob_is_noticed(self):
        """A hex secret spelled only in a-f is still a secret"""
        assert self._noticed("deadbeefdeadbeefdeadbeefcafefeedcafefeed")

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-05: the '.' separators fail BASE64ISH_RE, so a JWT is "
               "not seen as high-entropy",
    )
    def test_jwt_is_noticed(self):
        """A JWT is a credential whatever its separators do to the shape test"""
        assert self._noticed(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiJDQU5BUllfSldUIn0"
            ".dBjftJeZ4CVPmB92K27uhbUJU1p1r6wW1gFWFOEjXk"
        )


# ==========================================================================
# Structured content inside element text
# ==========================================================================
class TestStructuredContent:
    """Secrets carried inside another format that happens to live in XML"""

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-06: element text is never parsed as JSON, so a "
               "secret-named JSON key is not reached",
    )
    def test_secret_in_embedded_json_is_redacted(self):
        """A secret-named JSON key must be reached"""
        out = redact(wrap('<cfg>{"api_secret": "CANARY_JSON_SECRET", "n": 3}</cfg>'))
        assert "CANARY_JSON_SECRET" not in out

    def test_secret_in_cdata_is_reached(self):
        """CDATA is flattened by ElementTree, so name rules still apply

        Pins the behaviour explicitly: a secret in a CDATA section inside a
        *secret-named* element is redacted, which proves CDATA content is not
        skipped wholesale.
        """
        out = redact(wrap("<password><![CDATA[CANARY_CDATA_SECRET]]></password>"))
        assert "CANARY_CDATA_SECRET" not in out

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-07: CDATA in a non-secret-named element gets no "
               "treatment beyond the name rules, so free-text secrets survive",
    )
    def test_secret_in_cdata_in_unnamed_element_is_redacted(self):
        """CDATA free text must be scanned like any other free text"""
        out = redact(wrap("<freeform><![CDATA[deploy key CANARY_CDATA_FREE]]></freeform>"))
        assert "CANARY_CDATA_FREE" not in out

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-08: element tails are only processed under --aggressive",
    )
    def test_secret_in_element_tail_is_reached(self):
        """Mixed-content tails are text too"""
        out = redact("<pfsense><notes><marker/>203.0.113.9</notes></pfsense>")
        assert "203.0.113.9" not in out


# ==========================================================================
# Tag- and attribute-name coverage
# ==========================================================================
class TestNameCoverage:
    """What the two name patterns do and do not agree about"""

    ALREADY_MATCHED = ["password", "passwd", "pass", "secret", "token",
                       "apikey", "privkey", "clientsecret", "passphrase", "psk"]

    # Names that carry credentials in real package configs but match neither
    # pattern. Each is a live false negative, not a hypothetical.
    UNMATCHED = ["pwd", "bearer", "salt", "seed", "otpseed", "digest",
                 "hash", "nonce", "keydata", "keystore", "authorization",
                 "sessionid", "totp"]

    @pytest.mark.parametrize("tag", ALREADY_MATCHED)
    def test_known_secret_tags_are_matched(self, tag):
        """Regression pin for the names that do work"""
        redactor = PfSenseRedactor()
        assert redactor._is_secret_tag(tag, tag)  # pylint: disable=protected-access

    @pytest.mark.parametrize("tag", UNMATCHED)
    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-09: SECRET_TAG_PATTERN does not cover these credential-"
               "bearing element names",
    )
    def test_unmatched_secret_tags_are_matched(self, tag):
        """Credential-bearing element names the pattern misses"""
        redactor = PfSenseRedactor()
        assert redactor._is_secret_tag(tag, tag)  # pylint: disable=protected-access

    @pytest.mark.parametrize(
        "name", ["bearer", "cookie", "signature", "credentials", "privkey",
                 "licensekey", "psk", "passphrase", "community"]
    )
    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-10: SECRET_TAG_PATTERN and SENSITIVE_ATTR_PATTERN "
               "disagree, so an element and an attribute of the same name get "
               "different treatment",
    )
    def test_element_and_attribute_patterns_agree(self, name):
        """The same name must mean the same thing either side"""
        denied = name in SECRET_TAG_DENYLIST
        as_element = bool(SECRET_TAG_PATTERN.search(name)) and not denied
        as_attribute = bool(SENSITIVE_ATTR_PATTERN.search(name))
        assert as_element == as_attribute, (
            f"'{name}': element={as_element} attribute={as_attribute}"
        )

    def test_mixed_case_tag_is_matched(self):
        """Regression pin: _normalise_tag lower-cases, so case cannot evade"""
        out = redact(wrap("<ApiKey>CANARY_MIXEDCASE</ApiKey><PASSWORD>CANARY_UPPER</PASSWORD>"))
        assert "CANARY_MIXEDCASE" not in out
        assert "CANARY_UPPER" not in out

    def test_namespaced_tag_is_matched(self):
        """Regression pin: the {ns} prefix is stripped before matching"""
        out = redact(
            '<pfsense xmlns:p="urn:example"><cfg><p:password>CANARY_NS</p:password></cfg></pfsense>'
        )
        assert "CANARY_NS" not in out


# ==========================================================================
# Privacy identifiers outside the known-tag allowlist
# ==========================================================================
class TestIdentifierCoverage:
    """IP and domain redaction is gated on IP_CONTAINING_ELEMENTS by default"""

    def test_public_ip_in_known_element_is_redacted(self):
        """The control: a listed element does get scanned"""
        out = redact(wrap("<dnsserver>198.18.51.77</dnsserver>"))
        assert "198.18.51.77" not in out

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-11: an element outside IP_CONTAINING_ELEMENTS keeps its "
               "public addresses unless --aggressive is used",
    )
    def test_public_ip_in_unknown_element_is_redacted(self):
        """An unlisted element leaks the address"""
        out = redact(wrap("<syslogtarget>198.18.51.77</syslogtarget>"))
        assert "198.18.51.77" not in out

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-11: the same applies to hostnames in unknown elements",
    )
    def test_domain_in_unknown_element_is_redacted(self):
        """And the hostname beside it"""
        out = redact(wrap("<collector_note>ships to host.megacorp.example</collector_note>"))
        assert "megacorp.example" not in out

    def test_credential_url_is_redacted_in_every_mode(self):
        """Regression pin - the strongest area of the codebase"""
        url = "https://svc:CANARY_URLPW@feeds.vendor.invalid/l?token=CANARY_QTOKEN"
        for kwargs in ({}, {"aggressive": True}, {"anonymise": True}):
            out = redact(wrap(f"<updateurl>{url}</updateurl>"), **kwargs)
            assert "CANARY_URLPW" not in out, kwargs
            assert "CANARY_QTOKEN" not in out, kwargs

    def test_feed_filename_is_not_mangled_into_a_domain(self):
        """Over-redaction is a failure too: a corrupted feed path helps nobody"""
        out = redact(wrap("<path>/var/db/pfblockerng/deny.megacorp.example.txt</path>"))
        assert "deny.megacorp.example.txt" in out or "example.com" not in out


# ==========================================================================
# Sample previews shown by --dry-run-verbose
# ==========================================================================
class TestPreviewLeakage:
    """The preview exists to be safe to paste into a ticket or CI log"""

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-12: _mask_fqdn_sample keeps the registrable domain, so "
               "the organisation is named in the 'safe' preview",
    )
    def test_fqdn_preview_hides_the_registrable_domain(self):
        """The preview must not name the organisation"""
        redactor = PfSenseRedactor(dry_run_verbose=True)
        masked = redactor._safe_mask_for_sample(  # pylint: disable=protected-access
            "vpn.internal.megacorp-holdings.example", "FQDN"
        )
        assert "megacorp-holdings" not in masked

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-12: _mask_ip_sample keeps three of four octets, which "
               "identifies the network",
    )
    def test_ip_preview_hides_the_network(self):
        """Nor identify the network"""
        redactor = PfSenseRedactor(dry_run_verbose=True)
        masked = redactor._safe_mask_for_sample("198.18.240.17", "IP")  # pylint: disable=protected-access
        assert "198.18" not in masked

    def test_url_preview_redacts_embedded_credentials(self):
        """Regression pin: the preview must not print a live token"""
        redactor = PfSenseRedactor(dry_run_verbose=True)
        masked = redactor._safe_mask_for_sample(  # pylint: disable=protected-access
            "https://admin:CANARY_PW@host.example/x?token=CANARY_TOKEN", "URL"
        )
        assert "CANARY_PW" not in masked
        assert "CANARY_TOKEN" not in masked


# ==========================================================================
# End-to-end over the adversarial corpus
# ==========================================================================
class TestAdversarialCorpusEndToEnd:
    """The corpus, through the real CLI, in the mode the README leads with"""

    def test_default_mode_produces_valid_xml(self, adversarial_canary, run_redactor):
        """Whatever else it does, the output must parse"""
        result = run_redactor(adversarial_canary, "--stdout")
        assert result.returncode == 0
        ET.fromstring(result.stdout)

    def test_input_is_never_modified(self, adversarial_canary, run_redactor, tmp_path):
        """No read-only mode may touch the source"""
        before = adversarial_canary.read_bytes()
        run_redactor(adversarial_canary, tmp_path / "out.xml")
        run_redactor(adversarial_canary, "--stdout")
        run_redactor(adversarial_canary, "--dry-run-verbose")
        assert adversarial_canary.read_bytes() == before

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-01/02/03: private key material survives default-mode "
               "redaction of the adversarial corpus",
    )
    def test_no_key_material_survives_default_mode(self, adversarial_canary, run_redactor):
        """The mode the README leads with must not emit a private key"""
        result = run_redactor(adversarial_canary, "--stdout")
        assert not find_key_material(result.stdout)

    def test_no_key_material_survives_aggressive_mode(self, adversarial_canary, run_redactor):
        """--aggressive does clear these, but by shape rather than by decoding

        Worth pinning because the mechanism is incidental: the base64 wrappings
        in the corpus happen to mix character classes, so _is_high_entropy_value
        catches them. An encoding that produced a single character class would
        not be caught (FINDING-04), which is why this passing does not make
        FINDING-03 moot.
        """
        result = run_redactor(adversarial_canary, "--stdout", "--aggressive")
        assert not find_key_material(result.stdout)

    def test_baseline_secrets_always_die(self, adversarial_canary, run_redactor):
        """The classes the tool claims to cover must be gone in every mode"""
        always = {"CANARY_ADV_BCRYPT_BASELINE_HASH_VALUE",
                  "CANARY_ADV_AUTHKEYS_BASELINE",
                  "CANARY_ADV_ROCOMMUNITY_BASELINE",
                  "CANARY_ADV07_URLPASS",
                  "CANARY_ADV07_QUERYTOKEN",
                  "CANARY_ADV10_MIXEDCASE",
                  "CANARY_ADV10_UPPERCASE"}
        for flags in ([], ["--aggressive"], ["--anonymise"], ["--redact-descriptions"]):
            result = run_redactor(adversarial_canary, "--stdout", *flags)
            survivors = find_markers(result.stdout) & always
            assert not survivors, f"{flags or 'default'}: {sorted(survivors)}"

    def test_idempotent_across_modes(self, adversarial_canary, run_redactor, tmp_path):
        """redact(redact(x)) must reveal nothing redact(x) did not"""
        for name, flags in [("default", []), ("aggr", ["--aggressive"]),
                            ("anon", ["--anonymise"])]:
            once = run_redactor(adversarial_canary, "--stdout", *flags).stdout
            staged = tmp_path / f"{name}.xml"
            staged.write_text(once)
            twice = run_redactor(staged, "--stdout", *flags).stdout

            assert not (find_markers(twice) - find_markers(once)), name
            assert not (find_key_material(twice) - find_key_material(once)), name
