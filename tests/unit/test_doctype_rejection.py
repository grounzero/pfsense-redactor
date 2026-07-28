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
    PfSenseRedactor,
    _declares_doctype,
    _skip_prolog_noise,
)

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
    """_declares_doctype on the shapes a prolog can take"""

    def test_plain_doctype_detected(self, tmp_path):
        """The ordinary case: a DOCTYPE straight after the XML declaration"""
        path = write(tmp_path, ENTITY_BOMB)

        assert _declares_doctype(path)

    def test_no_doctype_accepted(self, tmp_path):
        """A normal config declares nothing"""
        path = write(tmp_path, MINIMAL_CONFIG)

        assert not _declares_doctype(path)

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

        assert _declares_doctype(path)

    def test_comment_without_doctype_accepted(self, tmp_path):
        """Padding alone is not grounds for refusal"""
        padding = 'P' * (_chunk() * 2)
        path = write(
            tmp_path,
            f'<?xml version="1.0"?>\n<!--{padding}-->\n<pfsense><a>1</a></pfsense>'
        )

        assert not _declares_doctype(path)

    def test_lowercase_doctype_detected(self, tmp_path):
        """XML requires the upper-case spelling; refuse the other one here

        Rather than leave it to the parser, so the outcome does not depend on
        which parser is in use.
        """
        path = write(tmp_path, '<!doctype pfsense><pfsense><a>1</a></pfsense>')

        assert _declares_doctype(path)

    def test_utf8_bom_skipped(self, tmp_path):
        """A byte-order mark must not shift the declaration out of view"""
        path = tmp_path / 'bom.xml'
        path.write_bytes(b'\xef\xbb\xbf' + ENTITY_BOMB.encode('utf-8'))

        assert _declares_doctype(str(path))

    def test_multiple_comments_and_pis_skipped(self, tmp_path):
        """Whitespace, several comments and a PI may all precede the DOCTYPE"""
        path = write(
            tmp_path,
            '<?xml version="1.0"?>\n\n  <!-- one -->\n<!-- two -->\n'
            '<?target data?>\n  <!DOCTYPE pfsense>\n<pfsense><a>1</a></pfsense>'
        )

        assert _declares_doctype(path)

    def test_doctype_inside_comment_not_detected(self, tmp_path):
        """A DOCTYPE mentioned in a comment is text, not a declaration"""
        path = write(
            tmp_path,
            '<!-- no <!DOCTYPE here -->\n<pfsense><a>1</a></pfsense>'
        )

        assert not _declares_doctype(path)

    def test_empty_file_accepted(self, tmp_path):
        """Nothing to refuse; ET.parse reports the real problem"""
        path = write(tmp_path, '')

        assert not _declares_doctype(path)

    def test_unterminated_comment_accepted(self, tmp_path):
        """Malformed input is the parser's to describe, not this guard's"""
        path = write(tmp_path, '<!-- never closed\n<pfsense><a>1</a></pfsense>')

        assert not _declares_doctype(path)

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

        assert _declares_doctype(path)


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
