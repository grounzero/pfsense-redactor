"""
Tests for the DOCTYPE guard on input files.

pfSense never emits a DOCTYPE, so one in the input means the file did not come
from pfSense untouched. ElementTree does not resolve external entities - a
SYSTEM entity raises ParseError, so there is no XXE - but it does expand
internal ones, and a few hundred bytes of nested definitions expand to
gigabytes. The guard refuses the file rather than parsing it.
"""
import xml.etree.ElementTree as ET

import pytest

from pfsense_redactor.redactor import (
    _PROLOG_MAX,
    PfSenseRedactor,
    _prolog_refusal_reason,
    _skip_prolog_noise,
)


def declares_doctype(path):
    """Whether the prolog is refused specifically because of a DOCTYPE

    Checking the reason, not merely that something was refused, keeps these
    tests from passing for the wrong cause once the size cap also refuses.
    """
    reason = _prolog_refusal_reason(path)
    return reason is not None and 'DOCTYPE' in reason

MINIMAL_CONFIG = '<?xml version="1.0"?>\n<pfsense><version>1.0</version></pfsense>'

ENTITY_BOMB = '''<?xml version="1.0"?>
<!DOCTYPE pfsense [
<!ENTITY a "aaaaaaaaaa">
<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<pfsense><version>&c;</version></pfsense>'''


def write(tmp_path, content, name='config.xml'):
    """Write a config file and return its path as a string"""
    path = tmp_path / name
    path.write_text(content, encoding='utf-8')
    return str(path)


class TestDoctypeDetection:
    """_prolog_refusal_reason on the shapes a prolog can take"""

    def test_plain_doctype_detected(self, tmp_path):
        """The ordinary case: a DOCTYPE straight after the XML declaration"""
        path = write(tmp_path, ENTITY_BOMB)

        assert declares_doctype(path)

    def test_no_doctype_accepted(self, tmp_path):
        """A normal config declares nothing"""
        path = write(tmp_path, MINIMAL_CONFIG)

        assert not declares_doctype(path)

    def test_doctype_behind_oversized_comment_detected(self, tmp_path):
        """A comment larger than the read chunk must not hide the DOCTYPE

        This is the regression that motivates scanning the whole prolog. A
        fixed-size prefix check reports success while letting the file through,
        which is worse than no guard at all.
        """
        padding = 'P' * (_chunk() * 2)
        path = write(
            tmp_path,
            f'<?xml version="1.0"?>\n<!--{padding}-->\n{ENTITY_BOMB.split(chr(10), 1)[1]}'
        )

        assert declares_doctype(path)

    def test_comment_without_doctype_accepted(self, tmp_path):
        """Padding alone is not grounds for refusal"""
        padding = 'P' * (_chunk() * 2)
        path = write(
            tmp_path,
            f'<?xml version="1.0"?>\n<!--{padding}-->\n<pfsense><a>1</a></pfsense>'
        )

        assert not declares_doctype(path)

    def test_lowercase_doctype_detected(self, tmp_path):
        """XML requires the upper-case spelling; refuse the other one here

        Rather than leave it to the parser, so the outcome does not depend on
        which parser is in use.
        """
        path = write(tmp_path, '<!doctype pfsense><pfsense><a>1</a></pfsense>')

        assert declares_doctype(path)

    def test_utf8_bom_skipped(self, tmp_path):
        """A byte-order mark must not shift the declaration out of view"""
        path = tmp_path / 'bom.xml'
        path.write_bytes(b'\xef\xbb\xbf' + ENTITY_BOMB.encode('utf-8'))

        assert declares_doctype(str(path))

    def test_multiple_comments_and_pis_skipped(self, tmp_path):
        """Whitespace, several comments and a PI may all precede the DOCTYPE"""
        path = write(
            tmp_path,
            '<?xml version="1.0"?>\n\n  <!-- one -->\n<!-- two -->\n'
            '<?target data?>\n  <!DOCTYPE pfsense>\n<pfsense><a>1</a></pfsense>'
        )

        assert declares_doctype(path)

    def test_doctype_inside_comment_not_detected(self, tmp_path):
        """A DOCTYPE mentioned in a comment is text, not a declaration"""
        path = write(
            tmp_path,
            '<!-- no <!DOCTYPE here -->\n<pfsense><a>1</a></pfsense>'
        )

        assert not declares_doctype(path)

    def test_empty_file_accepted(self, tmp_path):
        """Nothing to refuse; ET.parse reports the real problem"""
        path = write(tmp_path, '')

        assert not declares_doctype(path)

    def test_unterminated_comment_accepted(self, tmp_path):
        """Malformed input is the parser's to describe, not this guard's"""
        path = write(tmp_path, '<!-- never closed\n<pfsense><a>1</a></pfsense>')

        assert not declares_doctype(path)

    @pytest.mark.parametrize('boundary_offset', range(-2, 3))
    def test_doctype_split_across_read_boundary(self, tmp_path, boundary_offset):
        """The declaration must be found even when a read splits it in two"""
        # Pad so '<!DOCTYPE' straddles the chunk boundary at several offsets.
        prefix = '<?xml version="1.0"?>'
        padding_len = _chunk() - len(prefix) - len('<!--') - len('-->') + boundary_offset
        path = write(
            tmp_path,
            f'{prefix}<!--{"P" * padding_len}--><!DOCTYPE pfsense>'
            '<pfsense><a>1</a></pfsense>'
        )

        assert declares_doctype(path)


class TestPrologSizeCap:
    """The cap bounds the scan without opening a way past it

    Rescanning a growing buffer is quadratic, so an unbounded prolog lets a
    large file cost seconds of CPU. The cap fixes that, but only safely if
    exceeding it refuses the file - stopping the scan and parsing anyway would
    put back the very bypass the whole-prolog scan exists to close.
    """

    def test_oversized_prolog_refused(self, tmp_path):
        """A prolog past the cap is refused, with the size given as the reason"""
        padding = 'P' * (_PROLOG_MAX + 1024)
        path = write(
            tmp_path,
            f'<?xml version="1.0"?>\n<!--{padding}-->\n<pfsense><a>1</a></pfsense>'
        )

        reason = _prolog_refusal_reason(path)

        assert reason is not None
        assert 'prolog' in reason

    def test_cap_does_not_become_a_bypass(self, tmp_path):
        """A DOCTYPE hidden past the cap must not be let through

        The reason differs - the scan stops before reaching the declaration -
        but the file is still refused, which is the property that matters.
        """
        padding = 'P' * (_PROLOG_MAX + 1024)
        path = write(
            tmp_path,
            f'<?xml version="1.0"?>\n<!--{padding}-->\n'
            '<!DOCTYPE pfsense [ <!ENTITY a "aaaa"> ]>\n<pfsense><a>&a;</a></pfsense>'
        )

        assert _prolog_refusal_reason(path) is not None

    def test_large_file_with_small_prolog_accepted(self, tmp_path):
        """The cap measures the prolog, not the file

        A config far larger than the cap is ordinary and must still parse; only
        the bytes before the root element are counted.
        """
        body = '<a>' + ('x' * (_PROLOG_MAX * 2)) + '</a>'
        path = write(tmp_path, f'<?xml version="1.0"?>\n<pfsense>{body}</pfsense>')

        assert _prolog_refusal_reason(path) is None

    def test_prolog_just_under_cap_still_scanned(self, tmp_path):
        """Right below the cap the DOCTYPE is still found, not skipped"""
        padding = 'P' * (_PROLOG_MAX - 4096)
        path = write(
            tmp_path,
            f'<?xml version="1.0"?>\n<!--{padding}-->\n'
            '<!DOCTYPE pfsense>\n<pfsense><a>1</a></pfsense>'
        )

        assert declares_doctype(path), 'must be caught for the DOCTYPE, not the size'


class TestSkipPrologNoise:
    """_skip_prolog_noise reports where the prolog ends"""

    def test_returns_none_when_construct_is_truncated(self):
        """None means 'read more', not 'nothing here'"""
        assert _skip_prolog_noise(b'<!-- unterminated', 0) is None

    def test_stops_at_root_element(self):
        """A start tag is not noise, so scanning stops there"""
        data = b'<!-- c --><pfsense>'

        assert _skip_prolog_noise(data, 0) == data.index(b'<pfsense>')

    def test_stops_at_doctype(self):
        """The DOCTYPE is not skippable; the caller inspects it"""
        data = b'  <?xml version="1.0"?>  <!DOCTYPE r>'

        assert _skip_prolog_noise(data, 0) == data.index(b'<!DOCTYPE')


class TestRedactConfigRefusesDoctype:
    """End to end: the file is refused before any parsing happens"""

    def test_entity_bomb_refused(self, tmp_path, caplog):
        """redact_config fails, and says why"""
        redactor = PfSenseRedactor()
        output = tmp_path / 'out.xml'

        result = redactor.redact_config(write(tmp_path, ENTITY_BOMB), str(output))

        assert result is False
        assert not output.exists(), 'nothing should be written'
        assert 'DOCTYPE' in caplog.text

    def test_ordinary_config_still_processed(self, tmp_path):
        """The guard does not stand in the way of a normal file"""
        redactor = PfSenseRedactor()
        output = tmp_path / 'out.xml'

        result = redactor.redact_config(write(tmp_path, MINIMAL_CONFIG), str(output))

        assert result is True
        assert ET.parse(str(output)).getroot().tag == 'pfsense'


def _chunk() -> int:
    """The guard's read size, so the boundary tests track it if it changes"""
    from pfsense_redactor.redactor import _PROLOG_CHUNK

    return _PROLOG_CHUNK
