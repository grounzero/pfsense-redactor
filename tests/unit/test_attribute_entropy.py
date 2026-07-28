"""
Tests for high-entropy values in attributes reaching the retained-value report.

SENSITIVE_ATTR_PATTERN matches on an attribute's *name*. Key material sitting in
an attribute named something unremarkable therefore used to be invisible twice
over: not redacted, and not counted among the retained high-entropy values that
--fail-on-warn gates on. A CI check passed on a file whose own output had never
mentioned it.

Reported rather than redacted by default, deliberately. No pfSense config
examined in testing uses XML attributes at all, so this covers third-party
packages rather than an observed leak, and rewriting values by default on that
evidence would over-redact for everyone. --aggressive still redacts.

This does not close CANARY_ATTR_PLAIN, and is not meant to. That marker is prose
in a note attribute; the entropy heuristic requires 32+ characters with no
spaces, so it cannot match. --redact-descriptions is what covers it.
"""
import xml.etree.ElementTree as ET

import pytest

from pfsense_redactor.redactor import PfSenseRedactor

# 62 base64-shaped characters in an attribute whose name says nothing
BLOB = 'MIIDXTCCAkWgAwIBAgIJAKL0UG6mRkSPMA0GCSqGSIb3DQEBCwUAMEUxCzAJBg'
DOC = f'<pfsense><installedpackages><p><thing marker="{BLOB}">x</thing></p></installedpackages></pfsense>'


def redact(xml=DOC, **kwargs):
    """Redact a document and return (redactor, serialised output)"""
    redactor = PfSenseRedactor(**kwargs)
    root = ET.fromstring(xml)
    redactor.redact_element(root)
    return redactor, ET.tostring(root, encoding='unicode')


class TestDefaultModeReports:
    """The gap this closes: accounted for, not silently kept"""

    def test_value_is_retained(self):
        """Default mode does not rewrite it"""
        _, out = redact()

        assert BLOB in out

    def test_it_is_counted(self):
        """Which is what --fail-on-warn gates on"""
        redactor, _ = redact()

        assert redactor.stats['high_entropy_retained'] == 1

    def test_the_path_names_the_attribute(self):
        """'element[@attr]' - the notation docs/benchmark.md already uses"""
        redactor, _ = redact()

        assert redactor.high_entropy_paths == ['pfsense/installedpackages/p/thing[@marker]']

    def test_ordinary_values_are_not_reported(self):
        """A short or prose-shaped value is not key material"""
        redactor, _ = redact(
            '<pfsense><a><thing note="WAN uplink, second floor" id="7">x</thing></a></pfsense>'
        )

        assert redactor.stats['high_entropy_retained'] == 0

    def test_prose_long_enough_to_qualify_on_length_is_still_ignored(self):
        """Spaces disqualify a value, so notes do not become false positives

        This is also why the heuristic cannot close CANARY_ATTR_PLAIN.
        """
        prose = 'ISP support line pin is on the card in the rack cabinet'
        redactor, _ = redact(f'<pfsense><a><thing note="{prose}">x</thing></a></pfsense>')

        assert redactor.stats['high_entropy_retained'] == 0


class TestAggressiveRedacts:
    """The documented remedy works for attributes as it does for elements"""

    def test_value_is_replaced(self):
        _, out = redact(aggressive=True)

        assert BLOB not in out

    def test_placeholder_matches_the_element_path(self):
        """_redact_unknown_blob_element uses the same one for the same reason"""
        _, out = redact(aggressive=True)

        assert '[REDACTED_CERT_OR_KEY]' in out

    def test_nothing_is_left_to_report(self):
        """Redacted values are not also counted as retained"""
        redactor, _ = redact(aggressive=True)

        assert redactor.stats['high_entropy_retained'] == 0

    def test_it_is_counted_as_a_redaction(self):
        redactor, _ = redact(aggressive=True)

        assert redactor.stats['certs_redacted'] >= 1


class TestNameMatchingStillWins:
    """The pre-existing behaviour must not be disturbed"""

    def test_secret_named_attribute_is_still_redacted_by_name(self):
        """Short enough that entropy would never have caught it"""
        _, out = redact('<pfsense><a><thing password="hunter2">x</thing></a></pfsense>')

        assert 'hunter2' not in out
        assert '[REDACTED]' in out

    def test_a_name_match_is_not_also_reported_as_retained(self):
        """It was redacted, so there is nothing left to review"""
        redactor, _ = redact(f'<pfsense><a><thing api_key="{BLOB}">x</thing></a></pfsense>')

        assert redactor.stats['high_entropy_retained'] == 0
        assert redactor.stats['secrets_redacted'] >= 1

    @pytest.mark.parametrize('attr', ['descr', 'note', 'comment'])
    def test_description_attributes_under_the_flag(self, attr):
        """--redact-descriptions still covers free prose by name"""
        _, out = redact(
            f'<pfsense><a><thing {attr}="ISP pin 4471">x</thing></a></pfsense>',
            redact_descriptions=True
        )

        assert 'ISP pin 4471' not in out


class TestThroughTheCli:
    """A count that never reaches the shell is not a gate"""

    def test_fail_on_warn_stops_on_an_attribute_blob(self, cli_runner, tmp_path):
        """The whole point: CI can now see this"""
        source = tmp_path / 'config.xml'
        source.write_text(f'<?xml version="1.0"?>{DOC}', encoding='utf-8')

        exit_code, _, stderr = cli_runner.run(
            str(source), flags=['--stdout', '--fail-on-warn'], expect_success=False
        )

        assert exit_code != 0
        assert 'thing[@marker]' in stderr

    def test_aggressive_reopens_the_gate(self, cli_runner, tmp_path):
        """The remedy the warning names actually works"""
        source = tmp_path / 'config.xml'
        source.write_text(f'<?xml version="1.0"?>{DOC}', encoding='utf-8')

        exit_code, stdout, _ = cli_runner.run(
            str(source), flags=['--stdout', '--aggressive', '--fail-on-warn'],
            expect_success=False
        )

        assert exit_code == 0
        assert BLOB not in stdout
