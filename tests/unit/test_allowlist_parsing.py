"""Direct unit tests for allow-list file parsing

parse_allowlist_file was previously exercised only end to end through the CLI,
which left its line-classification and error paths without direct coverage.
These tests pin the current behaviour so it can be refactored safely.
"""
import ipaddress

import pytest

from pfsense_redactor.redactor import parse_allowlist_file


def write(tmp_path, content, name='allowlist.txt'):
    """Write an allow-list file and return its path as a string"""
    path = tmp_path / name
    path.write_text(content, encoding='utf-8')
    return str(path)


class TestLineClassification:
    """Each line is classified as an IP, a CIDR network, or a domain"""

    def test_plain_ipv4_and_ipv6(self, tmp_path):
        """Bare addresses land in the IP set as written"""
        ips, networks, domains = parse_allowlist_file(
            write(tmp_path, '8.8.8.8\n2001:db8::1\n')
        )

        assert ips == {'8.8.8.8', '2001:db8::1'}
        assert networks == []
        assert domains == set()

    def test_cidr_networks(self, tmp_path):
        """CIDR entries become network objects, not IP strings"""
        _, networks, _ = parse_allowlist_file(
            write(tmp_path, '10.0.0.0/8\n2001:db8::/32\n')
        )

        assert networks == [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('2001:db8::/32'),
        ]

    def test_host_bits_set_are_accepted(self, tmp_path):
        """strict=False, so 10.1.2.3/8 is accepted and normalised"""
        _, networks, _ = parse_allowlist_file(write(tmp_path, '10.1.2.3/8\n'))

        assert networks == [ipaddress.ip_network('10.0.0.0/8')]

    def test_domains_are_lowercased(self, tmp_path):
        """Domain matching is case-insensitive"""
        _, _, domains = parse_allowlist_file(
            write(tmp_path, 'Time.NIST.gov\nPOOL.ntp.org\n')
        )

        assert domains == {'time.nist.gov', 'pool.ntp.org'}

    def test_unparseable_entries_are_treated_as_domains(self, tmp_path):
        """Anything that is not an IP or CIDR falls through to the domain set"""
        _, _, domains = parse_allowlist_file(
            write(tmp_path, 'not an ip\n999.999.999.999\n')
        )

        assert domains == {'not an ip', '999.999.999.999'}

    def test_mixed_file(self, tmp_path):
        """All three kinds coexist in one file"""
        ips, networks, domains = parse_allowlist_file(
            write(tmp_path, '8.8.8.8\n192.168.0.0/16\ntime.nist.gov\n')
        )

        assert ips == {'8.8.8.8'}
        assert networks == [ipaddress.ip_network('192.168.0.0/16')]
        assert domains == {'time.nist.gov'}


class TestIgnoredLines:
    """Comments, blanks and surrounding whitespace"""

    @pytest.mark.parametrize('content', [
        '',
        '\n\n\n',
        '# just a comment\n',
        '   \n\t\n',
        '# comment\n\n   # indented comment is not stripped first\n',
    ])
    def test_nothing_collected(self, tmp_path, content):
        """These files contribute no entries"""
        ips, networks, domains = parse_allowlist_file(write(tmp_path, content))

        assert (ips, networks, domains) == (set(), [], set())

    def test_surrounding_whitespace_stripped(self, tmp_path):
        """Entries are stripped before classification"""
        ips, _, domains = parse_allowlist_file(
            write(tmp_path, '   8.8.8.8   \n\t time.nist.gov\t\n')
        )

        assert ips == {'8.8.8.8'}
        assert domains == {'time.nist.gov'}

    def test_comment_after_entry_is_not_stripped(self, tmp_path):
        """Only whole-line comments are supported; trailing ones are not"""
        _, _, domains = parse_allowlist_file(
            write(tmp_path, '8.8.8.8 # google\n')
        )

        assert domains == {'8.8.8.8 # google'}


class TestMissingFile:
    """silent_if_missing distinguishes default files from explicit ones"""

    def test_silent_returns_empty(self, tmp_path):
        """Default allow-list files may simply not exist"""
        result = parse_allowlist_file(
            str(tmp_path / 'nope.txt'), silent_if_missing=True
        )

        assert result == (set(), [], set())

    def test_explicit_missing_file_exits(self, tmp_path):
        """An explicitly requested file that is absent is a fatal error"""
        with pytest.raises(SystemExit) as exc:
            parse_allowlist_file(str(tmp_path / 'nope.txt'))

        assert exc.value.code == 1

    def test_directory_instead_of_file_exits(self, tmp_path):
        """Passing a directory is an OSError path, also fatal"""
        with pytest.raises(SystemExit) as exc:
            parse_allowlist_file(str(tmp_path))

        assert exc.value.code == 1
