"""
Tests for --fail-on-warn as a CI gate.

The flag used to cover the root-tag check alone. A config carrying a value the
tool declined to redact printed "Review before sharing" and still exited 0, so
an automated check passed on a file its own output said to look at.

docs/use-cases.md recommends this flag for CI, so the gap was between what it
was documented to do and what it did.

Two layers here on purpose. The predicate and redact_config are exercised
in-process, which is precise and needs no coverage hook; the exit codes are
exercised through the CLI, because a return value that never reaches a shell is
not a gate. CLI runs go through the cli_runner fixture rather than a bare
subprocess.run so the child inherits COVERAGE_PROCESS_START.
"""
import xml.etree.ElementTree as ET

import pytest

from pfsense_redactor.redactor import PfSenseRedactor

# A high-entropy value in an element the tool does not recognise: retained by
# default, reported for review, and redacted under --aggressive.
UNKNOWN_BLOB = (
    '<?xml version="1.0"?><pfsense><installedpackages><mypkg><config>'
    '<blob>MIIDXTCCAkWgAwIBAgIJAKL0UG6mRkSPMA0GCSqGSIb3DQEBCwUAMEUxCzAJBg</blob>'
    '</config></mypkg></installedpackages></pfsense>'
)

CLEAN_CONFIG = '<?xml version="1.0"?><pfsense><version>23.09</version></pfsense>'
WRONG_ROOT = '<?xml version="1.0"?><notpfsense><a>1</a></notpfsense>'


def redact(tmp_path, xml, **kwargs):
    """Redact in-process. Returns (redactor, success)"""
    source = tmp_path / 'config.xml'
    source.write_text(xml, encoding='utf-8')
    redactor = PfSenseRedactor(**kwargs)
    ok = redactor.redact_config(str(source), str(tmp_path / 'out.xml'))
    return redactor, ok


def run_cli(cli_runner, tmp_path, xml, *flags):
    """Redact through the CLI. Returns (exit_code, stdout, stderr)"""
    source = tmp_path / 'config.xml'
    source.write_text(xml, encoding='utf-8')
    return cli_runner.run(
        str(source), flags=['--stdout', *flags], expect_success=False
    )


class TestTheGatePredicate:
    """_retained_values_are_acceptable, on its own"""

    def test_passes_when_the_flag_is_not_set(self):
        """Retained values are advisory by default"""
        redactor = PfSenseRedactor(fail_on_warn=False)
        redactor.stats['high_entropy_retained'] = 3

        assert redactor._retained_values_are_acceptable() is True

    def test_passes_when_nothing_was_retained(self):
        """The flag alone is not a failure"""
        redactor = PfSenseRedactor(fail_on_warn=True)

        assert redactor._retained_values_are_acceptable() is True

    def test_fails_when_both_are_true(self):
        """The one combination that should stop a build"""
        redactor = PfSenseRedactor(fail_on_warn=True)
        redactor.stats['high_entropy_retained'] = 1

        assert redactor._retained_values_are_acceptable() is False

    def test_failure_is_logged_with_the_count_and_a_remedy(self, caplog):
        """A CI failure is only useful if it says what to do next"""
        redactor = PfSenseRedactor(fail_on_warn=True)
        redactor.stats['high_entropy_retained'] = 2

        redactor._retained_values_are_acceptable()

        assert '2' in caplog.text
        assert '--aggressive' in caplog.text


class TestRedactConfigReturnValue:
    """The predicate reaching redact_config's return, in-process"""

    def test_retained_value_returns_false_and_writes_nothing(self, tmp_path):
        """A failed gate produces no output at all

        This asserted the opposite until 1.5.0: that the file was still
        written, so the operator could review the retained paths in it. That
        reasoning does not survive the case the gate exists for. The candidate
        can contain a private key in an element the tool did not recognise, and
        an artefact that exists is an artefact that gets uploaded, attached,
        or picked up by the next step in the pipeline. The gate has to prevent
        the file, not annotate it.

        The review path is still there and costs nothing: --dry-run reports the
        same retained paths and the same verification findings, and never
        wrote a file in the first place.
        """
        redactor, ok = redact(tmp_path, UNKNOWN_BLOB, fail_on_warn=True)

        assert redactor.stats['high_entropy_retained'] == 1
        assert ok is False
        assert not (tmp_path / 'out.xml').exists(), (
            'a failed gate must leave no artefact for someone to share'
        )

    def test_retained_value_returns_true_without_the_flag(self, tmp_path):
        """Default behaviour is unchanged"""
        _, ok = redact(tmp_path, UNKNOWN_BLOB)

        assert ok is True

    def test_aggressive_redacts_them_so_the_gate_passes(self, tmp_path):
        """The documented remedy works: nothing retained, nothing to fail on"""
        redactor, ok = redact(tmp_path, UNKNOWN_BLOB, fail_on_warn=True, aggressive=True)

        assert redactor.stats['high_entropy_retained'] == 0
        assert ok is True

    def test_clean_config_passes(self, tmp_path):
        """No retained values means no failure, flag or not"""
        _, ok = redact(tmp_path, CLEAN_CONFIG, fail_on_warn=True)

        assert ok is True

    def test_dry_run_is_gated_too(self, tmp_path):
        """Checking without writing must still be able to fail

        Otherwise the least destructive way to run this in CI is also the one
        that cannot report a problem.
        """
        source = tmp_path / 'config.xml'
        source.write_text(UNKNOWN_BLOB, encoding='utf-8')
        redactor = PfSenseRedactor(fail_on_warn=True)

        ok = redactor.redact_config(str(source), None, dry_run=True)

        assert ok is False

    def test_dry_run_without_the_flag_still_passes(self, tmp_path):
        """--dry-run alone stays advisory"""
        source = tmp_path / 'config.xml'
        source.write_text(UNKNOWN_BLOB, encoding='utf-8')

        assert PfSenseRedactor().redact_config(str(source), None, dry_run=True) is True

    def test_wrong_root_tag_still_fails(self, tmp_path):
        """The flag's original job must not be lost"""
        _, ok = redact(tmp_path, WRONG_ROOT, fail_on_warn=True)

        assert ok is False

    def test_wrong_root_tag_only_warns_without_the_flag(self, tmp_path):
        """Still a warning rather than an error by default"""
        _, ok = redact(tmp_path, WRONG_ROOT)

        assert ok is True


class TestExitCodeReachesTheShell:
    """A return value a pipeline never sees is not a gate"""

    @pytest.mark.parametrize('flags,expect_zero', [
        ((), True),
        (('--fail-on-warn',), False),
        (('--aggressive', '--fail-on-warn'), True),
        (('--dry-run', '--fail-on-warn'), False),
    ])
    def test_exit_codes(self, cli_runner, tmp_path, flags, expect_zero):
        """The full matrix, so a change to any one path is visible"""
        exit_code, _, _ = run_cli(cli_runner, tmp_path, UNKNOWN_BLOB, *flags)

        assert (exit_code == 0) is expect_zero

    def test_failure_message_reaches_stderr(self, cli_runner, tmp_path):
        """The operator needs to see why, not just a non-zero code"""
        _, _, stderr = run_cli(cli_runner, tmp_path, UNKNOWN_BLOB, '--fail-on-warn')

        assert 'high-entropy' in stderr
        assert '--aggressive' in stderr

    def test_no_xml_is_emitted_when_the_gate_fails(self, cli_runner, tmp_path):
        """The gate must prevent the artefact, not annotate it

        Replaces test_output_is_still_written_when_the_gate_fails, which
        asserted that the redacted document reached stdout even though the run
        had just reported failure. A pipeline that pipes stdout to a file, or
        a shell that redirects it, ends up with exactly the artefact the gate
        was asked to prevent.

        --dry-run remains the way to see what would be retained without
        producing anything.
        """
        exit_code, stdout, _ = run_cli(cli_runner, tmp_path, UNKNOWN_BLOB, '--fail-on-warn')

        assert exit_code != 0
        assert stdout.strip() == '', 'a failed gate emitted the document anyway'
        with pytest.raises(ET.ParseError):
            ET.fromstring(stdout or '')

    def test_wrong_root_tag_exit_code(self, cli_runner, tmp_path):
        """The pre-existing behaviour, through the shell"""
        exit_code, _, stderr = run_cli(cli_runner, tmp_path, WRONG_ROOT, '--fail-on-warn')

        assert exit_code != 0
        assert 'root tag' in stderr.lower()
