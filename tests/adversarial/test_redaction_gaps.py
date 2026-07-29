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

# Synthetic: HS256 header, a payload naming a canary subject, and a signature
# segment that is not a signature of anything.
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJDQU5BUllfSldUIn0"
    ".dBjftJeZ4CVPmB92K27uhbUJU1p1r6wW1gFWFOEjXk"
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

    def test_pem_in_unknown_element_is_redacted(self):
        """Key material must not depend on the element being recognised"""
        out = redact(wrap(f"<vendorblob>{CANARY_PEM}</vendorblob>"))
        assert "BEGIN RSA PRIVATE KEY" not in out
        assert "CANARYPRIVATEKEY" not in out

    def test_pem_in_unknown_element_is_redacted_under_aggressive(self):
        """The documented escape hatch must actually work"""
        out = redact(wrap(f"<vendorblob>{CANARY_PEM}</vendorblob>"), aggressive=True)
        assert "BEGIN RSA PRIVATE KEY" not in out

    def test_pem_in_attribute_is_redacted(self):
        """Nor on the attribute name being recognised"""
        out = redact(wrap(f'<endpoint privkey="{CANARY_PEM}"/>'))
        assert "BEGIN RSA PRIVATE KEY" not in out

    def test_pem_in_wholly_unremarkable_attribute_is_redacted(self):
        """Not even a name-pattern match: the value alone must be enough

        'privkey' now matches the unified name pattern, so it no longer proves
        the value path works. 'blob' matches nothing at all.
        """
        out = redact(wrap(f'<endpoint blob="{CANARY_PEM}"/>'))
        assert "BEGIN RSA PRIVATE KEY" not in out
        assert "CANARYPRIVATEKEY" not in out

    def test_base64_wrapped_pem_is_redacted(self):
        """One layer of encoding must not conceal a key"""
        import base64  # pylint: disable=import-outside-toplevel
        encoded = base64.b64encode(CANARY_PEM.encode()).decode()
        out = redact(wrap(f"<payload>{encoded}</payload>"))
        assert not find_key_material(out), "key material recoverable by decoding"

    def test_double_base64_wrapped_pem_is_redacted(self):
        """Nor two"""
        import base64  # pylint: disable=import-outside-toplevel
        once = base64.b64encode(CANARY_PEM.encode()).decode()
        twice = base64.b64encode(once.encode()).decode()
        out = redact(wrap(f"<blob>{twice}</blob>"))
        assert not find_key_material(out), "key material recoverable by decoding twice"

    def test_base64url_wrapped_pem_is_redacted(self):
        """The URL-safe alphabet is the same secret in a different spelling"""
        import base64  # pylint: disable=import-outside-toplevel
        encoded = base64.urlsafe_b64encode(CANARY_PEM.encode()).decode()
        out = redact(wrap(f"<payload>{encoded}</payload>"))
        assert not find_key_material(out)

    def test_unpadded_base64_wrapped_pem_is_redacted(self):
        """Values stored in attributes and JSON routinely lose their padding"""
        import base64  # pylint: disable=import-outside-toplevel
        encoded = base64.b64encode(CANARY_PEM.encode()).decode().rstrip("=")
        out = redact(wrap(f"<payload>{encoded}</payload>"))
        assert not find_key_material(out)

    @pytest.mark.parametrize(
        "label",
        ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY",
         "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "ED25519 PRIVATE KEY",
         "PGP PRIVATE KEY BLOCK", "OPENVPN STATIC KEY V1"],
    )
    def test_every_private_key_header_is_redacted(self, label):
        """One container header per supported form, in an unknown element"""
        pem = (f"-----BEGIN {label}-----\n"
               "CANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIV0123\n"
               f"-----END {label}-----")
        out = redact(wrap(f"<vendorblob>{pem}</vendorblob>"))

        assert f"BEGIN {label}" not in out, label
        assert "CANARYPRIVATEKEY" not in out, label

    def test_public_key_header_is_not_treated_as_private(self):
        """Over-redaction is a failure too: a public key is not a private one

        Pins the boundary of the unconditional rule, so widening it later is a
        deliberate act rather than a regex accident.
        """
        from pfsense_redactor.redactor import (  # pylint: disable=import-outside-toplevel
            contains_private_key_material,
        )
        pem = ("-----BEGIN PUBLIC KEY-----\n"
               "CANARYPUBLICKEYCANARYPUBLICKEYCANARYPUBLIC0123\n"
               "-----END PUBLIC KEY-----")

        assert not contains_private_key_material(pem)
        assert not contains_private_key_material("-----BEGIN CERTIFICATE-----\nAAAA\n")

    @pytest.mark.parametrize(
        "wrapper",
        ["{pem}", "   {pem}   ", "\n\n{pem}\n\n", "\t{pem}\t"],
        ids=["bare", "spaces", "newlines", "tabs"],
    )
    def test_surrounding_whitespace_does_not_conceal_a_key(self, wrapper):
        """Leading and trailing whitespace is not a hiding place"""
        out = redact(wrap(f"<vendorblob>{wrapper.format(pem=CANARY_PEM)}</vendorblob>"))
        assert "BEGIN RSA PRIVATE KEY" not in out

    def test_pem_is_redacted_in_a_known_field_too(self):
        """The known path must not regress while the unknown one is fixed"""
        out = redact(f"<pfsense><cert><refid>abc</refid><prv>{CANARY_PEM}</prv></cert></pfsense>")
        assert "BEGIN RSA PRIVATE KEY" not in out

    @pytest.mark.parametrize(
        "flags",
        [{}, {"aggressive": True}, {"anonymise": True}, {"redact_descriptions": True},
         {"keep_private_ips": True}],
        ids=["default", "aggressive", "anonymise", "descriptions", "keep-private"],
    )
    def test_pem_dies_in_every_mode(self, flags):
        """'Every mode' is the claim, so every mode is the test"""
        out = redact(wrap(f"<vendorblob>{CANARY_PEM}</vendorblob>"), **flags)
        assert "BEGIN RSA PRIVATE KEY" not in out, flags
        assert "CANARYPRIVATEKEY" not in out, flags


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

    def test_lowercase_only_blob_is_noticed(self):
        """Character-class uniformity must not confer invisibility"""
        assert self._noticed("canaryadvlowercaseonlysecretvaluehere")

    def test_uppercase_only_blob_is_noticed(self):
        """The same, in the other direction"""
        assert self._noticed("CANARYADVUPPERCASEONLYSECRETVALUEHERE")

    def test_digitless_hex_blob_is_noticed(self):
        """A hex secret spelled only in a-f is still a secret"""
        assert self._noticed("deadbeefdeadbeefdeadbeefcafefeedcafefeed")

    def test_digit_only_blob_is_noticed(self):
        """Nor does being all digits make a 40-character value ordinary"""
        assert self._noticed("8163264128256512102420484096819216384327")

    def test_jwt_is_noticed(self):
        """A JWT is a credential whatever its separators do to the shape test"""
        assert self._noticed(JWT)

    def test_jwt_is_redacted_not_merely_reported(self):
        """A JWT is unambiguous, so report-only is not good enough for it"""
        out = redact(wrap(f"<sometoken_field>{JWT}</sometoken_field>"))

        assert "eyJhbGciOiJIUzI1NiIs" not in out
        assert "[REDACTED]" in out

    @pytest.mark.parametrize(
        "value",
        [
            "host.internal.example",
            "1.2.3",
            "10.20.30.40",
            "one.two.three",
            "archive.tar.gz",
            "backup-2026-07-28.config.xml",
            "org.freedesktop.systemd1",
            "com.example.someverylongreversedpackagename",
        ],
    )
    def test_ordinary_dotted_strings_are_not_jwts(self, value):
        """The cost of a JWT detector is what else it decides is a JWT"""
        from pfsense_redactor.redactor import (  # pylint: disable=import-outside-toplevel
            contains_jwt,
        )
        assert not contains_jwt(value), value

    @pytest.mark.parametrize(
        "value",
        [
            "deadbeef",                                # short hex
            "550e8400-e29b-41d4-a716-446655440000",    # UUID
            "ac:de:48:00:11:22",                       # MAC
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",  # IPv6
            "This is an ordinary operator note about the WAN link",
            "https://feeds.example.net/lists/blocklist.txt",
            "<rule><descr>allow web</descr></rule>",
            "3",                                       # certificate serial
            "00a3f1",                                  # short certificate serial
            "1234567890",                              # short numeric identifier
            "0000000000000000000000000000000000000000",  # all-zero field
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",  # padding
        ],
    )
    def test_benign_values_are_not_opaque_secrets(self, value):
        """Every one of these appears in a real config and none is a secret"""
        assert not self._noticed(value), value


# ==========================================================================
# Structured content inside element text
# ==========================================================================
class TestStructuredContent:
    """Secrets carried inside another format that happens to live in XML"""

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-06: element text is never parsed as JSON, so a "
               "secret-named JSON key is not reached. Still open in the "
               "transformer; contained since 1.4.2 by the verifier's token "
               "scan, which makes --strict refuse to emit rather than emit it "
               "at exit 0 - see TestEmbeddedSecretsFailClosed",
    )
    def test_secret_in_embedded_json_is_redacted(self):
        """A secret-named JSON key must be reached"""
        out = redact(wrap('<cfg>{"api_secret": "CANARY_JSON_SECRET", "n": 3}</cfg>'))
        assert "CANARY_JSON_SECRET" not in out

    @pytest.mark.parametrize("descr", ["<descr></descr>", "<descr>   </descr>"],
                             ids=["empty", "whitespace"])
    def test_an_empty_description_is_left_alone(self, descr):
        """--redact-descriptions must not put a placeholder where nothing was

        Replacing an empty element with [REDACTED] invents a value the config
        never had, and a reader cannot tell that from a redacted one.
        """
        out = redact(wrap(f"<rule>{descr}</rule>"), redact_descriptions=True)
        assert "[REDACTED]" not in out

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
               "treatment beyond the name rules, so free-text secrets survive. "
               "Still open in the transformer; contained since 1.4.2 by the "
               "verifier's token scan - see TestEmbeddedSecretsFailClosed",
    )
    def test_secret_in_cdata_in_unnamed_element_is_redacted(self):
        """CDATA free text must be scanned like any other free text"""
        out = redact(wrap("<freeform><![CDATA[deploy key CANARY_CDATA_FREE]]></freeform>"))
        assert "CANARY_CDATA_FREE" not in out

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-08: element tails are only processed under "
               "--aggressive. Still open in the transformer; contained since "
               "1.4.2 by the verifier, which now tracks tails - see "
               "TestEmbeddedSecretsFailClosed",
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

    # Names that match the pattern but denote a choice, a length or a
    # reference. Each was observed in a real pfSense or package config.
    NOT_SECRETS = ["keylen", "certref", "caref", "keyid", "publickey",
                   "pass_order", "password_type", "sendcommunity",
                   "source_hash_key", "hash-algorithm", "hashalgo",
                   "digestalgo", "auth-retry-none"]

    # Innocent names that contain a secret-ish word as a substring. These are
    # what the word-anchored half of the pattern exists to protect.
    INNOCENT = ["author", "bypass", "compass_heading", "monkeys_allowed",
                "authserver", "authdomain", "proxy_authtype",
                "authentication_method", "enable_cookie", "normalize_cookies",
                "signature_algorithm"]

    @pytest.mark.parametrize("tag", UNMATCHED)
    def test_unmatched_secret_tags_are_matched(self, tag):
        """Credential-bearing element names the pattern used to miss"""
        redactor = PfSenseRedactor()
        assert redactor._is_secret_tag(tag, tag)  # pylint: disable=protected-access

    @pytest.mark.parametrize("tag", NOT_SECRETS)
    def test_deny_listed_names_stay_deny_listed(self, tag):
        """Widening the pattern must not consume the deny-list"""
        redactor = PfSenseRedactor()
        assert not redactor._is_secret_tag(tag, tag)  # pylint: disable=protected-access

    @pytest.mark.parametrize("name", INNOCENT)
    def test_innocent_names_are_not_classified_as_secrets(self, name):
        """A substring is not a meaning: 'author' is not 'auth'"""
        redactor = PfSenseRedactor()
        assert not redactor._is_secret_name(name), name  # pylint: disable=protected-access

    def test_digest_element_keeps_an_algorithm_name(self):
        """<digest>SHA384</digest> selects an algorithm and is not a secret"""
        out = redact("<pfsense><ipsec><phase1><digest>SHA384</digest></phase1></ipsec></pfsense>")
        assert "SHA384" in out

    def test_digest_element_with_children_is_not_read_as_an_algorithm_name(self):
        """A container is not a value

        <digest><item>..</item></digest> has no text of its own. Without the
        child guard, that empty text reads as "no value", the element is
        classified as an algorithm choice, and the whole secret-name treatment
        is skipped for it - including its attributes. The attribute below is
        redacted only because the guard fires first.
        """
        out = redact(
            '<pfsense><pkg><digest algo="CANARY_DIGEST_ATTR">'
            '<item>x</item></digest></pkg></pfsense>'
        )

        assert "CANARY_DIGEST_ATTR" not in out
        assert "<item>" in out, "the container was collapsed instead of traversed"

    def test_digest_element_loses_anything_else(self):
        """The same element holding a digest, rather than naming one, is a secret"""
        out = redact("<pfsense><pkg><digest>CANARY_DIGEST_VALUE</digest></pkg></pfsense>")
        assert "CANARY_DIGEST_VALUE" not in out

    @pytest.mark.parametrize(
        "name", ["bearer", "cookie", "signature", "credentials", "privkey",
                 "licensekey", "psk", "passphrase", "community"]
    )
    def test_element_and_attribute_patterns_agree(self, name):
        """The same name must mean the same thing either side"""
        denied = name in SECRET_TAG_DENYLIST
        as_element = bool(SECRET_TAG_PATTERN.search(name)) and not denied
        as_attribute = bool(SENSITIVE_ATTR_PATTERN.search(name))
        assert as_element == as_attribute, (
            f"'{name}': element={as_element} attribute={as_attribute}"
        )

    @pytest.mark.parametrize("name", ALREADY_MATCHED + UNMATCHED + NOT_SECRETS + INNOCENT)
    def test_the_same_name_decides_the_same_way_in_both_positions(self, name):
        """The parity law, stated over every name this file knows about

        Asserted through the predicate rather than the raw pattern, so the
        deny-list is part of the law rather than an exception to it.
        """
        redactor = PfSenseRedactor()
        as_element = redactor._is_secret_tag(name, name)  # pylint: disable=protected-access
        as_attribute = redactor._should_redact_attribute(name)  # pylint: disable=protected-access

        assert as_element == as_attribute, (
            f"'{name}': element={as_element} attribute={as_attribute}"
        )

    @pytest.mark.parametrize(
        "value,expected",
        [
            (CANARY_PEM, "private-key"),
            (JWT, "jwt"),
            ("aGVsbG8gd29ybGQxMjM0NTY3ODkwQUJDREVGRw==", None),
            ("deadbeefdeadbeefdeadbeefcafefeedcafefeed", None),
            ("an ordinary rule description", None),
            ("-----BEGIN PUBLIC KEY-----\nAAAA\n", None),
        ],
        ids=["pem", "jwt", "base64-blob", "hex", "prose", "public-key"],
    )
    def test_the_same_value_decides_the_same_way_in_both_positions(self, value, expected):
        """The value parity law, the counterpart of the name one above

        Private-key material and JWTs are removed in every mode whatever holds
        them, and the element and attribute paths must not disagree about which
        values those are. Both classify through one function, so this asserts
        the classification itself rather than each path separately.
        """
        from pfsense_redactor.redactor import (  # pylint: disable=import-outside-toplevel
            unambiguous_secret_kind,
        )
        assert unambiguous_secret_kind(value) == expected

    @pytest.mark.parametrize("value", [CANARY_PEM, JWT])
    def test_element_and_attribute_remove_the_same_values(self, value):
        """And the two paths act on that classification identically"""
        as_element = redact(wrap(f"<vendorblob>{value}</vendorblob>"))
        as_attribute = redact(wrap(f'<endpoint blob="{value}"/>'))

        for fragment in ("CANARYPRIVATEKEY", "BEGIN RSA PRIVATE KEY", "eyJhbGciOiJIUzI1NiIs"):
            assert fragment not in as_element, f"element kept {fragment}"
            assert fragment not in as_attribute, f"attribute kept {fragment}"

    def test_a_repeated_path_is_listed_once(self):
        """Two siblings of the same name produce one retained path, not two

        The path is computed from the element's ancestors and its own tag, so
        siblings share it. Without the de-duplication the summary repeats the
        same location, and an operator counting lines to judge how much is left
        to review gets the wrong number.
        """
        redactor = PfSenseRedactor()
        root = ET.fromstring(wrap(
            "<blob>canaryadvlowercaseonlysecretvaluehere</blob>"
            "<blob>CANARYADVUPPERCASEONLYSECRETVALUEHERE</blob>"
        ))
        redactor.redact_element(root)

        assert redactor.stats['high_entropy_retained'] == 2, "both must be counted"
        assert redactor.high_entropy_paths.count(
            'pfsense/installedpackages/vendorpkg/config/blob'
        ) == 1, redactor.high_entropy_paths

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

    def test_no_key_material_survives_default_mode(self, adversarial_canary, run_redactor):
        """The mode the README leads with must not emit a private key"""
        result = run_redactor(adversarial_canary, "--stdout")
        assert not find_key_material(result.stdout)

    def test_no_key_material_reaches_stderr_either(self, adversarial_canary, run_redactor):
        """A key printed in a diagnostic is still a key that left the machine"""
        for flags in ([], ["--aggressive"], ["--verbose"], ["--dry-run-verbose"],
                      ["--fail-on-warn"]):
            result = run_redactor(adversarial_canary, "--stdout", *flags)
            combined = result.stdout + result.stderr

            assert not find_key_material(combined), flags
            assert "CANARYADV02PRIVATEKEY" not in combined, flags
            assert "CANARYADV03PRIVATEKEY" not in combined, flags

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
