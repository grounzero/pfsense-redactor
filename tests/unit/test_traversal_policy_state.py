"""
Tests for redact_ips/redact_domains as per-run instance state.

These two are policy for a whole run, not a per-element decision, so they are
set once by redact_config rather than threaded through every method beneath it.
That removed two arguments from six signatures, but it moves a value that used
to be passed explicitly into state that persists on the instance, which is
worth pinning:

- redact_config must assign on every call, so a reused redactor cannot inherit
  the previous run's policy
- the defaults must stay permissive-to-redact, because redact_element is
  callable on a bare element and most unit tests drive it that way

redact_text keeps its explicit parameters. It is a leaf utility called directly
with varying flags, and nothing about this change should alter that.
"""
import xml.etree.ElementTree as ET

import pytest

from pfsense_redactor.redactor import PfSenseRedactor

CONFIG = (
    '<?xml version="1.0"?><pfsense><a>'
    '<ipaddr>10.1.2.3</ipaddr><host>fw.acme.example</host>'
    '</a></pfsense>'
)


def write(tmp_path, name='config.xml'):
    """A config carrying one IP and one domain"""
    source = tmp_path / name
    source.write_text(CONFIG, encoding='utf-8')
    return source


def run(redactor, tmp_path, **kwargs):
    """Redact and return the output text"""
    out = tmp_path / f'out-{len(list(tmp_path.iterdir()))}.xml'
    redactor.redact_config(str(write(tmp_path)), str(out), **kwargs)
    return out.read_text(encoding='utf-8')


class TestDefaults:
    """A freshly constructed redactor redacts both"""

    def test_both_flags_default_to_true(self):
        """redact_element on a bare element must not silently keep everything"""
        redactor = PfSenseRedactor()

        assert redactor.redact_ips is True
        assert redactor.redact_domains is True

    def test_bare_redact_element_still_redacts(self):
        """The path 143 existing unit tests take"""
        redactor = PfSenseRedactor()
        root = ET.fromstring(CONFIG)
        redactor.redact_element(root)
        out = ET.tostring(root, encoding='unicode')

        assert '10.1.2.3' not in out
        assert 'fw.acme.example' not in out


class TestRedactConfigSetsPolicy:
    """Each flag reaches the traversal"""

    @pytest.mark.parametrize('ips,domains,ip_kept,domain_kept', [
        (True, True, False, False),
        (False, True, True, False),
        (True, False, False, True),
        (False, False, True, True),
    ])
    def test_the_matrix(self, tmp_path, ips, domains, ip_kept, domain_kept):
        """All four combinations, which is what the reference snapshots cover"""
        out = run(PfSenseRedactor(), tmp_path, redact_ips=ips, redact_domains=domains)

        assert ('10.1.2.3' in out) is ip_kept
        assert ('fw.acme.example' in out) is domain_kept


class TestNoStateLeakBetweenRuns:
    """The risk this refactor introduces, closed on purpose

    The flags used to be passed per call, so nothing could carry over. Now they
    live on the instance, and redact_config assigns them every time precisely so
    a second run cannot inherit the first run's policy.
    """

    def test_permissive_run_does_not_leak_into_a_default_run(self, tmp_path):
        """The dangerous direction: a later run must not under-redact"""
        redactor = PfSenseRedactor()
        run(redactor, tmp_path, redact_ips=False, redact_domains=False)

        out = run(redactor, tmp_path)

        assert '10.1.2.3' not in out, 'previous run kept IPs and this one inherited it'
        assert 'fw.acme.example' not in out

    def test_default_run_does_not_leak_into_a_permissive_run(self, tmp_path):
        """And the other direction, so the flags are honoured either way"""
        redactor = PfSenseRedactor()
        run(redactor, tmp_path)

        out = run(redactor, tmp_path, redact_ips=False, redact_domains=False)

        assert '10.1.2.3' in out
        assert 'fw.acme.example' in out

    def test_the_attributes_reflect_the_last_run(self, tmp_path):
        """State is observable, so state should be correct"""
        redactor = PfSenseRedactor()
        run(redactor, tmp_path, redact_ips=False, redact_domains=True)

        assert redactor.redact_ips is False
        assert redactor.redact_domains is True


class TestRedactTextKeepsItsParameters:
    """The boundary this refactor deliberately did not cross"""

    def test_explicit_flags_still_honoured(self):
        """Called directly with flags by 11 existing tests"""
        redactor = PfSenseRedactor()

        assert '10.1.2.3' in redactor.redact_text('10.1.2.3', redact_ips=False)
        assert '10.1.2.3' not in redactor.redact_text('10.1.2.3', redact_ips=True)

    def test_its_parameters_win_over_instance_state(self):
        """They are independent, so an explicit argument is not second-guessed"""
        redactor = PfSenseRedactor()
        redactor.redact_ips = True

        assert '10.1.2.3' in redactor.redact_text('10.1.2.3', redact_ips=False)
