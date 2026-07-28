"""Phase 6: what the tool tells the operator, and whether it fails closed

A redactor's exit code and summary are the only things most users read. If a
run that left a private key in the output reports success, the tool has not
just failed to redact - it has certified the failure.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from .decode_scan import find_key_material


class TestFailClosed:
    """Unsafe output must not be distributable"""

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-21: retained high-entropy values warn but do not fail, "
               "so a run that left a private key in the output exits 0",
    )
    def test_retained_key_material_fails_the_run(self, adversarial_canary, run_redactor):
        """Output holding a private key must not exit 0"""
        result = run_redactor(adversarial_canary, "--stdout")

        assert find_key_material(result.stdout), "fixture no longer leaks - update the test"
        assert result.returncode != 0, (
            "exit 0 on output containing a private key certifies the leak"
        )

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-22: --fail-on-warn reports failure only after the "
               "output has already been written, so the gate does not prevent "
               "the unsafe artefact from existing",
    )
    def test_fail_on_warn_writes_no_output(self, adversarial_canary, run_redactor, tmp_path):
        """The gate must prevent the artefact, not just report on it"""
        out = tmp_path / "out.xml"

        result = run_redactor(adversarial_canary, out, "--fail-on-warn")

        assert result.returncode != 0, "fixture no longer trips the gate"
        assert not out.exists(), (
            f"the gate failed but still produced {out.stat().st_size} bytes "
            f"of output for someone to share"
        )

    def test_fail_on_warn_does_fail(self, adversarial_canary, run_redactor):
        """Regression pin: the gate itself works, whatever its timing"""
        result = run_redactor(adversarial_canary, "--stdout", "--fail-on-warn")
        assert result.returncode != 0

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-23: only 0 and 1 are used, so a caller cannot tell a "
               "refused input from a retained secret from a write failure",
    )
    def test_exit_codes_distinguish_failure_kinds(self, tmp_path, run_redactor,
                                                  adversarial_canary):
        """A CI job needs to tell apart why a run failed"""
        malformed = tmp_path / "bad.xml"
        malformed.write_text("<pfsense><unclosed></pfsense>")

        parse_failure = run_redactor(malformed, "--stdout").returncode
        gate_failure = run_redactor(adversarial_canary, "--stdout", "--fail-on-warn").returncode

        assert parse_failure != gate_failure, (
            f"both failure kinds exit {parse_failure}; a CI job cannot tell "
            f"'this file is not parseable' from 'this file still has secrets'"
        )


class TestUnsupportedInput:
    """Structures the tool has no basis for understanding"""

    def test_unknown_root_tag_warns(self, tmp_path, run_redactor):
        """A non-pfSense root is surfaced to the operator"""
        config = tmp_path / "other.xml"
        config.write_text("<opnsense><system><password>CANARY_PW</password></system></opnsense>")

        result = run_redactor(config, "--stdout")
        assert "Warning" in result.stderr and "pfsense" in result.stderr

    def test_unknown_root_tag_fails_under_fail_on_warn(self, tmp_path, run_redactor):
        """And is fatal when the gate is asked for"""
        config = tmp_path / "other.xml"
        config.write_text("<opnsense><system><password>CANARY_PW</password></system></opnsense>")

        result = run_redactor(config, "--stdout", "--fail-on-warn")
        assert result.returncode != 0

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-24: the config's own <version> is never inspected, so "
               "a schema the tool has never seen is accepted silently",
    )
    def test_unsupported_config_version_is_reported(self, tmp_path, run_redactor):
        """An unrecognised schema version is named, not ignored"""
        config = tmp_path / "future.xml"
        config.write_text(
            "<pfsense><version>99.9</version><system><password>CANARY_PW</password>"
            "</system></pfsense>"
        )

        result = run_redactor(config, "--stdout")

        # stderr only: stdout carries the XML declaration, whose own
        # version="1.0" would satisfy any naive search for the word.
        assert "99.9" in result.stderr, (
            "nothing in the run tells the operator the schema is unrecognised"
        )


class TestImplicitConfiguration:
    """Security behaviour must not change because of where you ran the tool"""

    @pytest.fixture
    def workdir_with_allowlist(self, canary_copy, tmp_path):
        """A working directory containing an implicit .pfsense-allowlist"""
        (tmp_path / ".pfsense-allowlist").write_text(
            "# picked up silently from the current directory\n"
            "megacorp-holdings.example\n"
            "198.18.51.77\n"
        )
        return tmp_path

    def test_implicit_allowlist_changes_the_output(self, workdir_with_allowlist, run_redactor):
        """Establishes that the file really does take effect"""
        with_list = run_redactor("config.xml", "--stdout", cwd=workdir_with_allowlist).stdout
        (workdir_with_allowlist / ".pfsense-allowlist").unlink()
        without = run_redactor("config.xml", "--stdout", cwd=workdir_with_allowlist).stdout

        assert with_list != without, "the implicit allow-list had no effect"

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-25: the 'Loaded default allow-list' notice is "
               "suppressed under --stdout and --dry-run, the two modes most "
               "likely to be scripted",
    )
    def test_implicit_allowlist_is_announced_in_stdout_mode(self, workdir_with_allowlist,
                                                            run_redactor):
        """Weakened redaction must never be silent"""
        result = run_redactor("config.xml", "--stdout", cwd=workdir_with_allowlist)
        assert "allow-list" in result.stderr.lower(), (
            "redaction was weakened by a file in the working directory and "
            "the run never said so"
        )

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-25: same suppression under --dry-run",
    )
    def test_implicit_allowlist_is_announced_in_dry_run(self, workdir_with_allowlist,
                                                        run_redactor):
        """Same requirement in the mode used to decide about sharing"""
        result = run_redactor("config.xml", "--dry-run", cwd=workdir_with_allowlist)
        combined = result.stdout + result.stderr
        assert "allow-list" in combined.lower()

    def test_no_default_allowlist_disables_it(self, workdir_with_allowlist, run_redactor):
        """Regression pin for the opt-out"""
        with_list = run_redactor("config.xml", "--stdout", cwd=workdir_with_allowlist).stdout
        without = run_redactor(
            "config.xml", "--stdout", "--no-default-allowlist", cwd=workdir_with_allowlist
        ).stdout
        assert with_list != without


class TestMachineReadableAssurance:
    """A sharing decision should be checkable by something other than a human"""

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-26: there is no machine-readable report; the retained "
               "paths and counts exist only as prose on stderr",
    )
    def test_a_structured_report_is_available(self, adversarial_canary, run_redactor, tmp_path):
        """A sharing gate needs something other than prose to read"""
        import json  # pylint: disable=import-outside-toplevel

        report = tmp_path / "report.json"
        result = run_redactor(adversarial_canary, "--dry-run", "--report-json", report)

        assert result.returncode == 0, f"flag not accepted: {result.stderr.strip()[:200]}"
        assert report.exists(), "no report written"

        data = json.loads(report.read_text())
        assert "retained" in data or "high_entropy_retained" in data

    def test_retained_paths_are_named_on_stderr(self, adversarial_canary, run_redactor):
        """What exists today: prose, but at least specific prose"""
        result = run_redactor(adversarial_canary, "--stdout")
        assert "high-entropy value(s) retained" in result.stderr
        assert "telemetryagent/config/vendorblob" in result.stderr
        assert "endpoint[@privkey]" in result.stderr

    def test_summary_does_not_claim_more_than_it_did(self, adversarial_canary, run_redactor):
        """The summary must not read as a clean bill of health when it is not"""
        result = run_redactor(adversarial_canary, "--stdout")
        assert "Redaction summary" in result.stderr
        assert "Review before sharing" in result.stderr, (
            "the retained-value warning must sit alongside the success summary"
        )


class TestDryRunSafety:
    """--dry-run is what people run before deciding to share"""

    def test_dry_run_writes_no_file(self, canary_copy, run_redactor, tmp_path):
        """Regression pin: --dry-run touches nothing"""
        out = tmp_path / "out.xml"
        run_redactor(canary_copy, out, "--dry-run")
        assert not out.exists()

    def test_dry_run_verbose_prints_no_raw_secret(self, adversarial_canary, run_redactor):
        """The preview must not become the leak it exists to prevent"""
        result = run_redactor(adversarial_canary, "--dry-run-verbose")
        combined = result.stdout + result.stderr

        for marker in ("CANARY_ADV07_URLPASS", "CANARY_ADV07_QUERYTOKEN",
                       "CANARY_ADV_ROCOMMUNITY_BASELINE"):
            assert marker not in combined, marker
        assert "BEGIN RSA PRIVATE KEY" not in combined

    def test_dry_run_verbose_output_is_not_xml(self, adversarial_canary, run_redactor):
        """A preview that emitted the document would defeat --dry-run"""
        result = run_redactor(adversarial_canary, "--dry-run-verbose")
        with pytest.raises(ET.ParseError):
            ET.fromstring(result.stdout or "<empty/>x")
