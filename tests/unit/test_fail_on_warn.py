"""
Tests for --fail-on-warn as a CI gate.

The flag used to cover the root-tag check alone. A config carrying a value the
tool declined to redact printed "Review before sharing" and still exited 0, so
an automated check passed on a file its own output said to look at.

docs/use-cases.md recommends this flag for CI, so the gap was between what it
was documented to do and what it did.
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent

# A high-entropy value in an element the tool does not recognise: retained by
# default, reported for review, and redacted under --aggressive.
UNKNOWN_BLOB = (
    '<?xml version="1.0"?><pfsense><installedpackages><mypkg><config>'
    '<blob>MIIDXTCCAkWgAwIBAgIJAKL0UG6mRkSPMA0GCSqGSIb3DQEBCwUAMEUxCzAJBg</blob>'
    '</config></mypkg></installedpackages></pfsense>'
)

CLEAN_CONFIG = '<?xml version="1.0"?><pfsense><version>23.09</version></pfsense>'


def run(tmp_path, xml, *flags):
    """Redact a config to stdout and return the CompletedProcess"""
    source = tmp_path / 'config.xml'
    source.write_text(xml, encoding='utf-8')
    return subprocess.run(
        [sys.executable, '-m', 'pfsense_redactor', str(source), '--stdout', *flags],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT), check=False
    )


class TestRetainedValuesFailTheBuild:
    """The behaviour change"""

    def test_retained_value_warns_but_passes_without_the_flag(self, tmp_path):
        """Default behaviour is unchanged - the warning is advisory"""
        result = run(tmp_path, UNKNOWN_BLOB)

        assert result.returncode == 0
        assert 'high-entropy' in result.stderr

    def test_retained_value_fails_with_the_flag(self, tmp_path):
        """The gate now closes on exactly the case the warning describes"""
        result = run(tmp_path, UNKNOWN_BLOB, '--fail-on-warn')

        assert result.returncode != 0
        assert 'high-entropy' in result.stderr

    def test_failure_message_says_how_to_resolve_it(self, tmp_path):
        """A CI failure is only useful if it says what to do next"""
        result = run(tmp_path, UNKNOWN_BLOB, '--fail-on-warn')

        assert '--aggressive' in result.stderr

    def test_aggressive_redacts_them_so_the_gate_passes(self, tmp_path):
        """The documented remedy actually works

        --aggressive redacts these values, so nothing is retained and there is
        nothing left to fail on.
        """
        result = run(tmp_path, UNKNOWN_BLOB, '--aggressive', '--fail-on-warn')

        assert result.returncode == 0
        assert 'high-entropy' not in result.stderr

    def test_clean_config_passes(self, tmp_path):
        """No retained values means no failure, flag or not"""
        assert run(tmp_path, CLEAN_CONFIG, '--fail-on-warn').returncode == 0


class TestDryRunIsGatedToo:
    """--dry-run is the natural CI shape: check without writing anything"""

    def test_dry_run_fails_on_retained_values(self, tmp_path):
        """Checking without writing must still be able to fail

        Otherwise the least destructive way to run this in CI is also the one
        that cannot report a problem.
        """
        result = run(tmp_path, UNKNOWN_BLOB, '--dry-run', '--fail-on-warn')

        assert result.returncode != 0

    def test_dry_run_without_the_flag_still_passes(self, tmp_path):
        """--dry-run alone stays advisory"""
        assert run(tmp_path, UNKNOWN_BLOB, '--dry-run').returncode == 0


class TestRootTagCheckStillWorks:
    """The behaviour the flag already had must not be lost"""

    def test_wrong_root_tag_still_fails(self, tmp_path):
        """This was the flag's original and only job"""
        result = run(tmp_path, '<?xml version="1.0"?><notpfsense><a>1</a></notpfsense>',
                     '--fail-on-warn')

        assert result.returncode != 0
        assert 'root tag' in result.stderr.lower()

    def test_wrong_root_tag_warns_without_the_flag(self, tmp_path):
        """Still a warning rather than an error by default"""
        result = run(tmp_path, '<?xml version="1.0"?><notpfsense><a>1</a></notpfsense>')

        assert result.returncode == 0
        assert 'root tag' in result.stderr.lower()


class TestExitCodeIsUsableInCI:
    """What a pipeline actually consumes"""

    @pytest.mark.parametrize('flags,expected_zero', [
        ((), True),
        (('--fail-on-warn',), False),
        (('--aggressive', '--fail-on-warn'), True),
        (('--dry-run', '--fail-on-warn'), False),
    ])
    def test_exit_codes(self, tmp_path, flags, expected_zero):
        """The full matrix, so a change to any one path is visible"""
        result = run(tmp_path, UNKNOWN_BLOB, *flags)

        assert (result.returncode == 0) is expected_zero

    def test_output_is_still_written_when_the_gate_fails(self, tmp_path):
        """Failing the build must not mean losing the redacted file

        The retained values were reported, not leaked - the operator still
        wants the output in order to review those paths.
        """
        result = run(tmp_path, UNKNOWN_BLOB, '--fail-on-warn')

        assert result.returncode != 0
        assert re.search(r'<pfsense>', result.stdout), 'redacted output should still be produced'
