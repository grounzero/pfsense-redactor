"""Phase 7: whether the shipped corpus score measures what it claims

tests/integration/test_canary_corpus.py counts survivors with a literal
``CANARY_[A-Z0-9_]+`` regex over the output, and the README publishes the
result as 44/46. Any marker the config author encoded is invisible to that
count - so a genuine leak can sit in the corpus, be asserted as retained by
another test in the same suite, and still not move the published number.

These tests measure the measurement.
"""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from .decode_scan import find_key_material, find_markers

CORPUS = Path(__file__).resolve().parent.parent / "corpus" / "canary-corpus.xml"


@pytest.fixture
def corpus() -> Path:
    """The shipped canary corpus the published score is measured against"""
    if not CORPUS.exists():  # pragma: no cover - repo integrity
        pytest.skip(f"missing corpus: {CORPUS}")
    return CORPUS


class TestDecodeAwareScanner:
    """The scanner itself, before it is trusted to judge anything"""

    def test_finds_a_literal_marker(self):
        """The plain case the corpus scorer already handles"""
        assert "CANARY_PLAIN" in find_markers("value CANARY_PLAIN here")

    def test_finds_a_single_base64_marker(self):
        """One layer of encoding must not hide a marker"""
        blob = base64.b64encode(b"CANARY_ONCE_WRAPPED").decode()
        assert "CANARY_ONCE_WRAPPED" in find_markers(blob)

    def test_finds_a_double_base64_marker(self):
        """Nor two"""
        once = base64.b64encode(b"CANARY_TWICE_WRAPPED").decode()
        twice = base64.b64encode(once.encode()).decode()
        assert "CANARY_TWICE_WRAPPED" in find_markers(twice)

    def test_finds_a_marker_split_across_lines(self):
        """Line wrapping must not hide a marker either"""
        assert "CANARY_SPLIT_VALUE" in find_markers("CANARY_\nSPLIT_\nVALUE")

    def test_finds_pem_through_base64(self):
        """Key material is recognised without a planted marker"""
        pem = b"-----BEGIN RSA PRIVATE KEY-----\nCANARY\n-----END RSA PRIVATE KEY-----"
        assert "RSA PRIVATE KEY" in find_key_material(base64.b64encode(pem).decode())

    def test_does_not_invent_markers(self):
        """The scanner must not manufacture findings"""
        assert not find_markers("ordinary configuration text with no markers")

    def test_decoding_is_depth_bounded(self):
        """The scanner must not become the unbounded-recursion bug it looks for"""
        payload = b"CANARY_DEEP"
        for _ in range(8):
            payload = base64.b64encode(payload)
        assert "CANARY_DEEP" not in find_markers(payload.decode(), max_depth=2)


class TestCorpusScoringIsIncomplete:
    """The published 44/46 does not account for encoded markers"""

    def test_corpus_contains_an_encoded_marker(self, corpus):
        """Establishes the premise: the corpus really does hold one"""
        text = corpus.read_text()
        literal = find_markers(text, max_depth=0)
        decoded = find_markers(text)

        assert decoded - literal, (
            "no encoded marker in the corpus - if one was removed, this "
            "finding is closed and the test should be deleted"
        )

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-27: the corpus score counts literal markers only, so "
               "the base64 canary that survives default mode is not in the "
               "denominator and cannot move the published 44/46",
    )
    def test_no_encoded_marker_survives_default_mode(self, corpus, run_redactor):
        """Encoded markers count against the score like any other"""
        result = run_redactor(corpus, "--stdout")

        literal = find_markers(result.stdout, max_depth=0)
        decoded = find_markers(result.stdout)

        assert not (decoded - literal), (
            f"markers recoverable only by decoding: {sorted(decoded - literal)}"
        )

    def test_strict_mode_leaves_no_encoded_marker(self, corpus, run_redactor, tmp_path):
        """Strict mode is where the encoded survivor is actually accounted for

        The default-mode gap above stands: the corpus score counts literal
        markers, and the base64 canary is not in its denominator. What strict
        mode adds is that the same marker cannot reach output at all - either
        it is redacted, or the run produces nothing.
        """
        out = tmp_path / "out.xml"
        result = run_redactor(corpus, out, "--strict")

        if result.returncode != 0:
            assert not out.exists()
            return

        literal = find_markers(out.read_text(), max_depth=0)
        decoded = find_markers(out.read_text())
        assert not (decoded - literal), sorted(decoded - literal)

    def test_aggressive_mode_clears_the_encoded_marker(self, corpus, run_redactor):
        """Pins the escape hatch, and scopes the finding to default mode"""
        result = run_redactor(corpus, "--stdout", "--aggressive")

        literal = find_markers(result.stdout, max_depth=0)
        decoded = find_markers(result.stdout)
        assert decoded == literal

    def test_no_key_material_survives_the_shipped_corpus(self, corpus, run_redactor):
        """The corpus's own key material must not survive any mode"""
        for flags in ([], ["--aggressive"], ["--anonymise"]):
            result = run_redactor(corpus, "--stdout", *flags)
            assert not find_key_material(result.stdout), flags


class TestPemInvariantIsNotVacuous:
    """A non-vacuous counterpart to tests/properties/test_invariants.py:89-124

    That test guards its assertion with `if has_pem_in_input:`, and no file in
    test-configs/ contains a PEM marker - so the loop body has never executed.
    The original is left alone; this asserts the same invariant against input
    that actually contains what the invariant is about.
    """

    PEM = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "CANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIVATEKEYCANARYPRIV0123\n"
        "-----END RSA PRIVATE KEY-----"
    )

    @pytest.fixture
    def config_with_pem(self, tmp_path) -> Path:
        """A config that actually contains the PEM the invariant is about"""
        config = tmp_path / "pem.xml"
        config.write_text(
            "<pfsense><system><user><name>admin</name></user></system>"
            f"<cert><refid>abc123</refid><crt>{self.PEM}</crt>"
            f"<prv>{self.PEM}</prv></cert></pfsense>"
        )
        return config

    def test_premise_holds(self, config_with_pem):
        """The guard the original test never got past"""
        assert "BEGIN RSA PRIVATE KEY" in config_with_pem.read_text()

    @pytest.mark.parametrize(
        "flags",
        [[], ["--aggressive"], ["--anonymise"], ["--keep-private-ips"],
         ["--redact-descriptions"]],
        ids=["default", "aggressive", "anonymise", "keep-private", "descriptions"],
    )
    def test_no_pem_marker_survives_any_mode(self, config_with_pem, run_redactor, flags):
        """The invariant tests/properties never got to assert"""
        result = run_redactor(config_with_pem, "--stdout", *flags)
        assert "BEGIN RSA PRIVATE KEY" not in result.stdout
        assert "CANARYPRIVATEKEY" not in result.stdout
