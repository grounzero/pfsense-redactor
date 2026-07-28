"""Bounded decoding, private-key recognition, JWT and opaque-value shape

These are the primitives the redactor's classification rests on, so they are
tested directly as well as through the tree walk. The bounds matter as much as
the detection: a scanner that decodes without limit is a denial of service
wearing a security control's clothes.

Every value here is synthetic. The "PEM" bodies are base64-legal runs of the
word CANARY and decode to nothing.
"""
import base64
import time

import pytest

from pfsense_redactor.redactor import (
    MAX_DECODE_DEPTH,
    MAX_DECODED_BYTES,
    MIN_OPAQUE_ENTROPY_BITS,
    OPAQUE_UNIFORM_MIN_LENGTH,
    PfSenseRedactor,
    contains_jwt,
    contains_private_key_material,
    decoded_layers,
    shannon_entropy_bits,
)

PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "CANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIV0123\n"
    "-----END RSA PRIVATE KEY-----"
)

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJDQU5BUllfSldUIn0"
    ".dBjftJeZ4CVPmB92K27uhbUJU1p1r6wW1gFWFOEjXk"
)


def wrap_b64(value, times=1):
    """Base64-encode `value` `times` over"""
    data = value.encode() if isinstance(value, str) else value
    for _ in range(times):
        data = base64.b64encode(data)
    return data.decode()


class TestBoundedDecoding:
    """decoded_layers must find what is hidden and stop where it is told"""

    def test_finds_a_single_layer(self):
        """The ordinary case"""
        layers = decoded_layers(wrap_b64(PEM))
        assert any("BEGIN RSA PRIVATE KEY" in layer for layer in layers)

    def test_finds_a_double_layer(self):
        """Wrapping twice hides the marker from any first-layer heuristic"""
        layers = decoded_layers(wrap_b64(PEM, 2))
        assert any("BEGIN RSA PRIVATE KEY" in layer for layer in layers)

    def test_finds_a_triple_layer(self):
        """Three is the documented depth, so three must work"""
        layers = decoded_layers(wrap_b64(PEM, 3))
        assert any("BEGIN RSA PRIVATE KEY" in layer for layer in layers)

    def test_stops_at_the_documented_depth(self):
        """Four layers is past the bound, and the bound is the point"""
        layers = decoded_layers(wrap_b64(PEM, MAX_DECODE_DEPTH + 1))
        assert not any("BEGIN RSA PRIVATE KEY" in layer for layer in layers)

    def test_depth_argument_is_honoured(self):
        """Callers can tighten the bound; nobody can loosen it past the loop"""
        assert not decoded_layers(wrap_b64(PEM, 2), max_depth=1) or not any(
            "BEGIN RSA PRIVATE KEY" in layer
            for layer in decoded_layers(wrap_b64(PEM, 2), max_depth=1)
        )

    def test_invalid_base64_yields_nothing(self):
        """Strict validation, so text that was never encoded is not 'decoded'"""
        assert not decoded_layers("!!!! not base64 at all !!!!")

    def test_short_values_are_not_decoded_at_all(self):
        """Below the candidate floor there is no room to hide a key header"""
        assert not decoded_layers("QUJD")

    def test_unchanged_decoding_is_not_expanded_again(self):
        """A value that decodes to itself is a dead end, not a loop"""
        layers = decoded_layers("A" * 64)
        assert len(layers) <= MAX_DECODE_DEPTH

    def test_oversized_encoded_run_is_refused(self):
        """A run that would decode past the byte bound is skipped, not decoded"""
        oversized = wrap_b64("x" * (MAX_DECODED_BYTES * 2))
        started = time.monotonic()
        layers = decoded_layers(oversized)

        assert time.monotonic() - started < 10
        assert not any(len(layer) > MAX_DECODED_BYTES for layer in layers)

    def test_decoding_a_large_document_stays_quick(self):
        """The operation budget is shared, so many runs cost no more than a few"""
        text = " ".join(wrap_b64(f"value-number-{n}-padding") for n in range(5000))
        started = time.monotonic()
        decoded_layers(text)

        assert time.monotonic() - started < 10

    def test_input_is_never_returned_as_a_layer(self):
        """Returning the source would double-count it in every caller"""
        source = wrap_b64(PEM)
        assert source not in decoded_layers(source)


class TestPrivateKeyRecognition:
    """The one classification with no over-redaction trade-off"""

    @pytest.mark.parametrize(
        "label",
        ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY",
         "ED25519 PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY",
         "SSH2 ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK",
         "OPENVPN STATIC KEY V1"],
    )
    def test_recognises_every_supported_header(self, label):
        """One per container header the tool claims to recognise"""
        assert contains_private_key_material(f"-----BEGIN {label}-----\nAAAA\n")

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN RSA PUBLIC KEY-----",
            "-----BEGIN DH PARAMETERS-----",
            "-----BEGIN CERTIFICATE REQUEST-----",
            "the private key is stored elsewhere",
        ],
    )
    def test_does_not_overclaim(self, text):
        """A certificate, a public key and a sentence are not private keys"""
        assert not contains_private_key_material(text)

    def test_recognises_through_one_encoding(self):
        """An encoding is not a protection"""
        assert contains_private_key_material(wrap_b64(PEM))

    def test_recognises_through_two_encodings(self):
        """Nor two"""
        assert contains_private_key_material(wrap_b64(PEM, 2))

    def test_recognises_through_urlsafe_encoding(self):
        """The URL-safe alphabet is the same secret spelled differently"""
        assert contains_private_key_material(
            base64.urlsafe_b64encode(PEM.encode()).decode()
        )

    def test_recognises_without_padding(self):
        """Attributes and JSON routinely strip the padding"""
        assert contains_private_key_material(wrap_b64(PEM).rstrip("="))


class TestJwtRecognition:
    """A compact token, and the dotted strings that are not one"""

    def test_recognises_a_compact_jwt(self):
        """The ordinary case"""
        assert contains_jwt(JWT)

    def test_recognises_a_jwt_inside_a_header_value(self):
        """'Authorization: Bearer <token>' is where these actually live"""
        assert contains_jwt(f"Bearer {JWT}")

    def test_recognises_a_jwt_in_a_url_query(self):
        """Tokens reach configs in a query string as often as in a header"""
        assert contains_jwt(f"https://api.example.invalid/v1?access_token={JWT}")

    def test_recognises_a_long_jwt(self):
        """Length is not what identifies it, so length must not defeat it"""
        long_payload = base64.urlsafe_b64encode(
            b'{"sub":"' + b'CANARY' * 200 + b'"}'
        ).decode().rstrip("=")
        assert contains_jwt(f"eyJhbGciOiJIUzI1NiJ9.{long_payload}.c2lnbmF0dXJl")

    def test_recognises_a_whitespace_formatted_header(self):
        """A header serialised with spaces does not start with 'eyJ'"""
        header = base64.urlsafe_b64encode(b'{ "alg": "HS256" }').decode().rstrip("=")
        assert contains_jwt(f"{header}.eyJzdWIiOiJhIn0.c2lnbmF0dXJlc2lnbmF0dXJl")

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "no dots here at all",
            "host.internal.example",
            "vpn.corp.megacorp-holdings.example",
            "1.2.3",
            "23.09.1",
            "192.0.2.1",
            "2001:db8::1",
            "one.two.three",
            "archive.tar.gz",
            "config-backup-2026-07-28.old.xml",
            "com.example.averylongreversedpackagenameindeed",
            "/var/db/pfblockerng/deny.megacorp-holdings.example.txt",
        ],
    )
    def test_ordinary_dotted_strings_are_not_tokens(self, value):
        """The whole cost of this detector is what else it decides is a token"""
        assert not contains_jwt(value), value

    def test_three_long_segments_alone_are_not_enough(self):
        """The general shape only counts when segment one is a JOSE header"""
        assert not contains_jwt(
            "aaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccc"
        )


class TestEntropyAndShape:
    """The one heuristic of the three, and its thresholds"""

    def test_entropy_of_uniform_text_is_zero(self):
        """One repeated character carries no information"""
        assert shannon_entropy_bits("A" * 64) == 0.0

    def test_entropy_of_empty_text_is_zero(self):
        """And neither does nothing at all"""
        assert shannon_entropy_bits("") == 0.0

    def test_entropy_of_a_base64_secret_is_high(self):
        """The control for the floor below"""
        assert shannon_entropy_bits(wrap_b64(PEM)) > 4.0

    @pytest.mark.parametrize(
        "value",
        [
            "canaryadvlowercaseonlysecretvaluehere",
            "CANARYADVUPPERCASEONLYSECRETVALUEHERE",
            "deadbeefdeadbeefdeadbeefcafefeedcafefeed",
            "DEADBEEFDEADBEEFDEADBEEFCAFEFEEDCAFEFEED",
            "deadbeefdeadbeefdeadbeefdeadbeef",
            "8163264128256512102420484096819216384327",
            "aGVsbG8gd29ybGQxMjM0NTY3ODkwQUJDREVGRw==",
        ],
        ids=["lower", "upper", "hex-lower", "hex-upper", "hex-32", "digits", "mixed"],
    )
    def test_opaque_secrets_are_detected(self, value):
        """Single-character-class uniformity is not a disguise"""
        assert PfSenseRedactor()._is_high_entropy_value(value), value  # pylint: disable=protected-access

    @pytest.mark.parametrize(
        "value",
        [
            "deadbeef",
            "550e8400-e29b-41d4-a716-446655440000",
            "550E8400-E29B-41D4-A716-446655440000",
            "ac:de:48:00:11:22",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "This is an ordinary operator note about the WAN link and its ISP",
            "https://feeds.example.net/lists/blocklist.txt",
            "<rule><descr>allow web traffic from the office</descr></rule>",
            "3",
            "00a3f1",
            "1234567890",
            "0000000000000000000000000000000000000000",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "abababababababababababababababababababab",
        ],
        ids=["short-hex", "uuid", "uuid-upper", "mac", "ipv6", "prose", "url",
             "xml", "serial", "short-serial", "numeric-id", "zeroes", "padding",
             "repeated"],
    )
    def test_benign_values_are_not_detected(self, value):
        """Each of these appears in a real config and none is a secret"""
        assert not PfSenseRedactor()._is_high_entropy_value(value), value  # pylint: disable=protected-access

    def test_the_uniform_length_band_is_where_it_is_documented(self):
        """A single-class value just under the floor stays out of scope

        Pins the threshold rather than leaving it implicit, so moving it is a
        deliberate act with a visible cost.
        """
        redactor = PfSenseRedactor()
        just_under = "abcdefghij" * 4
        just_under = just_under[:OPAQUE_UNIFORM_MIN_LENGTH - 1]
        just_over = ("abcdefghij" * 4)[:OPAQUE_UNIFORM_MIN_LENGTH]

        assert not redactor._is_high_entropy_value(just_under)  # pylint: disable=protected-access
        assert redactor._is_high_entropy_value(just_over)  # pylint: disable=protected-access

    def test_the_entropy_floor_is_load_bearing(self):
        """Below it, a value satisfying the shape carries nothing"""
        assert shannon_entropy_bits("ab" * 32) < MIN_OPAQUE_ENTROPY_BITS
        assert not PfSenseRedactor()._is_high_entropy_value("ab" * 32)  # pylint: disable=protected-access


class TestNothingDecodedIsEverEmitted:
    """Decoded plaintext is the thing someone chose to encode"""

    def test_decoding_leaves_no_trace_in_logs(self, caplog):
        """The decoder must not log what it found, at any level"""
        import logging  # pylint: disable=import-outside-toplevel

        with caplog.at_level(logging.DEBUG, logger='pfsense_redactor'):
            assert contains_private_key_material(wrap_b64(PEM, 2))

        assert "BEGIN RSA PRIVATE KEY" not in caplog.text
        assert "CANARYPRIVATEKEY" not in caplog.text

    def test_decoded_content_is_not_placed_in_samples(self):
        """--dry-run-verbose prints samples, so samples must not carry it"""
        import xml.etree.ElementTree as ET  # pylint: disable=import-outside-toplevel

        redactor = PfSenseRedactor(dry_run_verbose=True)
        root = ET.fromstring(
            f"<pfsense><pkg><payload>{wrap_b64(PEM)}</payload></pkg></pfsense>"
        )
        redactor.redact_element(root)

        rendered = str(dict(redactor.samples))
        assert "BEGIN RSA PRIVATE KEY" not in rendered
        assert "CANARYPRIVATEKEY" not in rendered
