"""
Tests for resolving certificate references instead of inferring them from length.

A cert-named element holding a short value used to be kept on the strength of
its length alone: under CERT_MIN_LENGTH and without a PEM header, it was assumed
to be a refid and left readable. That is a proxy for meaning, and it is what let
CANARY_HAPROXYCERTS and CANARY_SSLOFFLOAD through the canary corpus.

The config already declares which references exist, so the value is resolved
against the <refid> elements in the same file. Resolves: keep, because a
reference helps a reader understand the structure and is not key material.
Does not resolve: redact, because nothing accounts for it.

The direction of the unresolved case is deliberate. Absent proof that a value is
a reference, it is treated as a secret - a config carrying no <refid> at all
therefore loses its short cert values, which is over-redaction in the safe
direction.
"""
import xml.etree.ElementTree as ET

import pytest

from pfsense_redactor.redactor import PfSenseRedactor

REFID = '5a04208c70f14'
OTHER_REFID = '5a04208c7c65a'

PEM = (
    '-----BEGIN CERTIFICATE-----\n'
    'MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKKzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n'
    '-----END CERTIFICATE-----'
)


def redact(xml, refids=(), **kwargs):
    """Drive redact_element directly with a known refid set"""
    redactor = PfSenseRedactor(**kwargs)
    redactor.known_refids = frozenset(refids)
    root = ET.fromstring(xml)
    redactor.redact_element(root)
    return ET.tostring(root, encoding='unicode')


class TestCollectingRefids:
    """The pre-pass that builds the lookup table"""

    def test_finds_refids_anywhere_in_the_tree(self):
        """Package cert stores do not reliably sit where the base system puts them"""
        root = ET.fromstring(
            f'<pfsense><cert><refid>{REFID}</refid></cert>'
            f'<installedpackages><p><refid>{OTHER_REFID}</refid></p></installedpackages>'
            '</pfsense>'
        )

        assert PfSenseRedactor._collect_refids(root) == {REFID, OTHER_REFID}

    def test_blank_and_missing_refids_are_skipped(self):
        """An empty <refid/> declares nothing and must not admit the empty string"""
        root = ET.fromstring('<pfsense><cert><refid/></cert><ca><refid>   </refid></ca></pfsense>')

        assert PfSenseRedactor._collect_refids(root) == frozenset()

    def test_no_refids_gives_an_empty_set(self):
        """Which resolves nothing, so short cert values are treated as secrets"""
        root = ET.fromstring('<pfsense><a>x</a></pfsense>')

        assert PfSenseRedactor._collect_refids(root) == frozenset()


class TestResolvableReferencesSurvive:
    """The reason short values were ever kept"""

    @pytest.mark.parametrize('tag', ['ssl_ca_cert', 'ssl_server_cert', 'ha_certificates'])
    def test_declared_reference_is_preserved(self, tag):
        """Real configs point at certificates this way throughout"""
        out = redact(f'<pfsense><a><{tag}>{REFID}</{tag}></a></pfsense>', refids=[REFID])

        assert REFID in out

    def test_several_references_all_declared(self):
        """HAProxy's ha_certificates can carry more than one"""
        out = redact(
            f'<pfsense><a><ha_certificates>{REFID},{OTHER_REFID}</ha_certificates></a></pfsense>',
            refids=[REFID, OTHER_REFID]
        )

        assert REFID in out
        assert OTHER_REFID in out

    def test_whitespace_separated_references(self):
        """The separator is not consistent across packages"""
        out = redact(
            f'<pfsense><a><ha_certificates>{REFID} {OTHER_REFID}</ha_certificates></a></pfsense>',
            refids=[REFID, OTHER_REFID]
        )

        assert OTHER_REFID in out


class TestUnresolvableValuesAreRedacted:
    """The gap this closes"""

    def test_undeclared_value_goes(self):
        """Nothing in the config accounts for it, so it is not a reference"""
        out = redact('<pfsense><a><ssloffloadcert>hunter2secret</ssloffloadcert></a></pfsense>')

        assert 'hunter2secret' not in out

    def test_partial_match_redacts_the_whole_value(self):
        """One token resolving does not make the rest of the value a reference

        Requiring every token to resolve is the safe direction: a mixed value is
        not purely a reference list, so all of it is suspect.
        """
        out = redact(
            f'<pfsense><a><ha_certificates>{REFID},hunter2secret</ha_certificates></a></pfsense>',
            refids=[REFID]
        )

        assert 'hunter2secret' not in out

    def test_a_config_with_no_refids_loses_its_short_cert_values(self):
        """Over-redaction in the safe direction, and the documented behaviour

        A fragment shared without its <cert> section cannot prove any of its
        references are references, so they are treated as secrets.
        """
        out = redact('<pfsense><a><ssl_ca_cert>abc123def456</ssl_ca_cert></a></pfsense>')

        assert 'abc123def456' not in out

    def test_it_is_redacted_as_a_secret_not_as_cert_material(self):
        """A short value with no PEM header demonstrably is not cert material"""
        out = redact('<pfsense><a><ssloffloadcert>hunter2secret</ssloffloadcert></a></pfsense>')

        assert '[REDACTED]' in out
        assert '[REDACTED_CERT_OR_KEY]' not in out


class TestWhatMustNotChange:
    """The surrounding behaviour this refines rather than replaces"""

    def test_pem_material_is_still_cert_redacted(self):
        """Resolution refines the short-value branch only"""
        out = redact(f'<pfsense><a><ha_certificates>{PEM}</ha_certificates></a></pfsense>')

        assert '[REDACTED_CERT_OR_KEY]' in out

    def test_long_values_are_still_cert_redacted(self):
        """Anything past CERT_MIN_LENGTH is material, whatever the refid table says"""
        blob = 'A1b2C3d4' * 8

        out = redact(f'<pfsense><a><ssl_ca_cert>{blob}</ssl_ca_cert></a></pfsense>')

        assert blob not in out
        assert '[REDACTED_CERT_OR_KEY]' in out

    @pytest.mark.parametrize('tag', ['crt', 'cert', 'public-key'])
    def test_material_holding_elements_are_untouched_by_resolution(self, tag):
        """CERT_KEY_ELEMENTS carry the material itself

        A short value in one is a truncated key or one of our own placeholders,
        never a refid, so resolving it would be answering the wrong question.
        """
        out = redact(f'<pfsense><a><{tag}>short</{tag}></a></pfsense>')

        assert 'short' in out

    def test_container_elements_are_not_mangled(self):
        """<cert> wraps <refid>/<crt>; its own text is the newline before them"""
        out = redact(
            f'<pfsense><cert>\n  <refid>{REFID}</refid>\n  <descr>Web</descr>\n</cert></pfsense>',
            refids=[REFID]
        )

        assert '<cert>' in out
        assert REFID in out
        assert '[REDACTED]' not in out

    def test_a_cert_store_that_is_itself_a_container(self):
        """The case the container guard actually exists for

        <cert> exits earlier because it holds material, so it never reaches the
        guard. HAProxy's <ha_certificates> wrapping <item> children does, and
        its text is only the newline before the first child.
        """
        out = redact(
            '<pfsense><a><ha_certificates>\n  <item>first</item>\n'
            '</ha_certificates></a></pfsense>'
        )

        assert '<item>first</item>' in out
        assert '[REDACTED]' not in out

    @pytest.mark.parametrize('text', ['', '   ', '\n  '])
    def test_empty_cert_elements_are_left_alone(self, text):
        """Nothing to resolve and nothing to leak"""
        out = redact(f'<pfsense><a><ha_certificates>{text}</ha_certificates></a></pfsense>')

        assert '[REDACTED]' not in out

    def test_separators_with_no_tokens_are_redacted(self):
        """A value that is punctuation only resolves to nothing

        It cannot be a reference list, so it takes the unresolved path rather
        than being waved through as empty.
        """
        out = redact('<pfsense><a><ha_certificates>,,</ha_certificates></a></pfsense>')

        assert '[REDACTED]' in out

    def test_numbered_material_elements_are_excluded_too(self):
        """Exclusion is by tag base, so <crt2> is still a material element"""
        out = redact('<pfsense><a><crt2>short</crt2></a></pfsense>')

        assert 'short' in out

    @pytest.mark.parametrize('placeholder', ['[REDACTED]', '[REDACTED_CERT_OR_KEY]'])
    def test_our_own_placeholders_are_left_alone(self, placeholder):
        """Redacting an already-redacted file must be a no-op

        Without this, '[REDACTED_CERT_OR_KEY]' fails to resolve on a second pass
        and degrades to the less informative '[REDACTED]'.
        """
        out = redact(
            f'<pfsense><a><ha_certificates>{placeholder}</ha_certificates></a></pfsense>'
        )

        assert placeholder in out


class TestThroughRedactConfig:
    """The refid table is built by redact_config, not by the caller"""

    def test_references_resolve_end_to_end(self, tmp_path):
        """A whole config, with the pre-pass running as it does in production"""
        source = tmp_path / 'config.xml'
        source.write_text(
            f'<?xml version="1.0"?><pfsense><cert><refid>{REFID}</refid></cert>'
            f'<installedpackages><h><config><ssloffloadcert>{REFID}</ssloffloadcert>'
            '<ha_certificates>undeclared99</ha_certificates>'
            '</config></h></installedpackages></pfsense>',
            encoding='utf-8'
        )
        out_file = tmp_path / 'out.xml'

        assert PfSenseRedactor().redact_config(str(source), str(out_file)) is True

        out = out_file.read_text(encoding='utf-8')
        assert REFID in out, 'a declared reference should survive'
        assert 'undeclared99' not in out, 'an undeclared value should not'

    def test_refids_declared_after_their_use_still_resolve(self, tmp_path):
        """The pre-pass runs over the whole tree before any redaction

        Element order in config.xml is not guaranteed, so a package section that
        precedes the <cert> block must still resolve against it.
        """
        source = tmp_path / 'config.xml'
        source.write_text(
            f'<?xml version="1.0"?><pfsense>'
            f'<installedpackages><h><config><ssloffloadcert>{REFID}</ssloffloadcert>'
            '</config></h></installedpackages>'
            f'<cert><refid>{REFID}</refid></cert></pfsense>',
            encoding='utf-8'
        )
        out_file = tmp_path / 'out.xml'
        PfSenseRedactor().redact_config(str(source), str(out_file))

        assert REFID in out_file.read_text(encoding='utf-8')
