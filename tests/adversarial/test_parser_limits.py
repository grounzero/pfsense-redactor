"""Phase 4: hostile-input safety and resource bounds

The prolog guard against DOCTYPE and entity expansion is already well covered
by tests/unit/test_doctype_rejection.py and is not repeated here. What is left
is the work the tool does *after* parsing, where the bounds are less explicit.
"""
from __future__ import annotations

import time
import xml.etree.ElementTree as ET

import pytest

from pfsense_redactor.redactor import PfSenseRedactor


def nested_config(depth: int) -> str:
    """A well-formed pfSense config nested `depth` elements deep"""
    return f"<pfsense>{'<a>' * depth}x{'</a>' * depth}</pfsense>"


class TestRecursionBounds:
    """redact_element recurses once per level of XML nesting"""

    def test_ordinary_nesting_is_fine(self):
        """A real config is a handful of levels deep; 200 is generous"""
        root = ET.fromstring(nested_config(200))
        PfSenseRedactor().redact_element(root)

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-13: redact_element has no depth bound, so nesting past "
               "the interpreter recursion limit raises RecursionError, which "
               "redact_config does not catch",
    )
    def test_deep_nesting_is_refused_not_crashed(self):
        """Nesting past the recursion limit must be handled, not fatal"""
        root = ET.fromstring(nested_config(2000))
        redactor = PfSenseRedactor()
        try:
            redactor.redact_element(root)
        except RecursionError:
            pytest.fail("RecursionError escaped redact_element")

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-13: the RecursionError reaches the shell as an "
               "unhandled traceback rather than a diagnosed refusal",
    )
    def test_deep_nesting_reports_cleanly_through_the_cli(self, tmp_path, run_redactor):
        """And must reach the shell as a diagnosis"""
        deep = tmp_path / "deep.xml"
        deep.write_text(nested_config(2000))

        result = run_redactor(deep, "--stdout")

        assert result.returncode != 0, "must not report success"
        assert "Traceback" not in result.stderr, (
            "an unhandled traceback is not a diagnosis, and it prints "
            "interpreter paths the operator did not ask for"
        )


class TestTextSizeBounds:
    """MAX_TEXT_CHUNK bounds the work, but silently discards the excess"""

    def test_oversized_text_is_bounded(self):
        """The bound itself works - this is the control"""
        redactor = PfSenseRedactor()
        started = time.monotonic()
        result = redactor.redact_text("A" * (redactor.MAX_TEXT_CHUNK + 200_000))
        assert time.monotonic() - started < 30
        assert len(result) <= redactor.MAX_TEXT_CHUNK

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-14: text over MAX_TEXT_CHUNK is truncated, so the "
               "output silently loses config data while the run reports success",
    )
    def test_oversized_text_is_not_silently_truncated(self, tmp_path, run_redactor):
        """Discarding config data is not a successful run"""
        oversized = "A" * 1_200_000
        config = tmp_path / "big.xml"
        config.write_text(
            f"<pfsense><system><hostname>{oversized}</hostname></system></pfsense>"
        )

        result = run_redactor(config, "--stdout")
        root = ET.fromstring(result.stdout)
        kept = root.find("system/hostname").text or ""

        assert len(kept) == len(oversized) or result.returncode != 0, (
            f"{len(oversized) - len(kept)} characters discarded, exit code "
            f"{result.returncode}"
        )


class TestPathologicalPatterns:
    """Regex passes over attacker-controlled text must stay near-linear"""

    @pytest.mark.parametrize(
        "text",
        [
            "a-" * 4000 + "!",                       # FQDN_RE label chain
            "x@" + "a." * 4000 + "!",                # EMAIL_RE domain chain
            "https://" + "a" * 4000 + "/" + "b" * 4000,
            "askpass " + "A" * 200_000 + "\t",       # BLOB_DIRECTIVE_RE lazy tail
        ],
        ids=["fqdn-chain", "email-chain", "long-url", "directive-tail"],
    )
    def test_pathological_text_completes_quickly(self, text):
        """A generous ceiling - catastrophic backtracking blows past it by orders"""
        redactor = PfSenseRedactor()
        started = time.monotonic()
        redactor.redact_text(text)
        assert time.monotonic() - started < 10

    def test_blob_element_with_pathological_line(self):
        """custom_options is scanned line by line, so it gets its own check"""
        redactor = PfSenseRedactor()
        root = ET.fromstring(
            "<pfsense><openvpn><custom_options>"
            + "askpass " + "A" * 200_000
            + "</custom_options></openvpn></pfsense>"
        )
        started = time.monotonic()
        redactor.redact_element(root)
        assert time.monotonic() - started < 10


class TestMalformedInput:
    """Malformed XML must be diagnosed, never half-processed"""

    @pytest.mark.parametrize(
        "content",
        [
            "<pfsense><unclosed></pfsense>",
            "<pfsense>\x00</pfsense>",
            "<pfsense><a attr='unterminated></a></pfsense>",
            "not xml at all",
            "<?xml version='1.0' encoding='utf-32'?><pfsense/>",
        ],
        ids=["unclosed", "nul-byte", "unterminated-attr", "not-xml", "bad-encoding"],
    )
    def test_malformed_input_writes_nothing(self, tmp_path, run_redactor, content):
        """A rejected input must leave no output behind"""
        config = tmp_path / "bad.xml"
        config.write_bytes(content.encode("utf-8", errors="ignore"))
        out = tmp_path / "out.xml"

        result = run_redactor(config, out)

        assert result.returncode != 0
        assert not out.exists(), "a rejected input must not leave an output file"
        assert "Traceback" not in result.stderr
