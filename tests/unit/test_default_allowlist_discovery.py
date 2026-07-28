"""
Tests for the default allow-list file being found, read and merged.

`.pfsense-allowlist` in the working directory is picked up with no flag at all,
which makes it the one allow-list source a user can forget they have. It is also
the source that was never exercised: _collect_allowlists was covered only
through --allowlist-file and the CLI flags, so the default-file path ran in
production and nowhere else.

--no-default-allowlist is the opt out, and needs a test for the same reason: a
flag that silently fails to disable something is worse than no flag.
"""
import argparse
import logging

import pytest

from pfsense_redactor.redactor import _collect_allowlists, find_default_allowlist_files

LOGGER = logging.getLogger('pfsense_redactor')


def make_args(**overrides):
    """A Namespace shaped like the one argparse hands _collect_allowlists"""
    defaults = {
        'no_default_allowlist': False,
        'allowlist_file': None,
        'allowlist_ips': [],
        'allowlist_domains': [],
        'dry_run': False,
        'stdout': True,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def collect(**overrides):
    """Run the collector with a Namespace built from the defaults above"""
    return _collect_allowlists(make_args(**overrides), LOGGER)


@pytest.fixture(name='in_dir_with_default')
def in_dir_with_default_fixture(tmp_path, monkeypatch):
    """Run inside a directory holding a .pfsense-allowlist file

    monkeypatch.chdir rather than passing a path, because discovery is by
    convention: the file is found relative to the working directory.
    """
    (tmp_path / '.pfsense-allowlist').write_text(
        '# defaults\n10.20.30.40\n172.16.0.0/12\ndefault.acme.example\n',
        encoding='utf-8'
    )
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestDiscovery:
    """find_default_allowlist_files looks in the working directory"""

    def test_local_file_is_found(self, in_dir_with_default):
        """The file the fixture just wrote"""
        found = find_default_allowlist_files()

        assert any(p.name == '.pfsense-allowlist' for p in found)

    def test_nothing_found_in_an_empty_directory(self, tmp_path, monkeypatch):
        """No file, no error: this runs on every invocation"""
        monkeypatch.chdir(tmp_path)

        assert all(p.name != '.pfsense-allowlist' for p in find_default_allowlist_files())


class TestDefaultFileIsMerged:
    """The path that previously ran only in production"""

    def test_entries_reach_the_allowlists(self, in_dir_with_default):
        """All three kinds from one file, no flags involved"""
        ips, networks, domains = collect()

        assert '10.20.30.40' in ips
        assert any(str(n) == '172.16.0.0/12' for n in networks)
        assert 'default.acme.example' in domains

    def test_default_and_explicit_file_both_apply(self, in_dir_with_default, tmp_path):
        """A later source adds to the default rather than replacing it"""
        explicit = tmp_path / 'extra.txt'
        explicit.write_text('192.0.2.1\nextra.acme.example\n', encoding='utf-8')

        ips, _, domains = collect(allowlist_file=str(explicit))

        assert {'10.20.30.40', '192.0.2.1'} <= ips
        assert {'default.acme.example', 'extra.acme.example'} <= domains

    def test_cli_flags_merge_on_top_of_the_default_file(self, in_dir_with_default):
        """Every source is additive, which is the documented behaviour"""
        ips, _, domains = collect(
            allowlist_ips=['198.51.100.7'], allowlist_domains=['CLI.acme.example']
        )

        assert {'10.20.30.40', '198.51.100.7'} <= ips
        assert 'cli.acme.example' in domains, 'CLI domains are lower-cased'


class TestOptOut:
    """--no-default-allowlist has to actually disable it"""

    def test_default_file_is_ignored(self, in_dir_with_default):
        """The early return, which nothing reached before"""
        ips, networks, domains = collect(no_default_allowlist=True)

        assert not ips
        assert not networks
        assert not domains

    def test_explicit_file_still_applies(self, in_dir_with_default, tmp_path):
        """Opting out of defaults must not disable an allow-list asked for by name"""
        explicit = tmp_path / 'extra.txt'
        explicit.write_text('192.0.2.1\n', encoding='utf-8')

        ips, _, _ = collect(no_default_allowlist=True, allowlist_file=str(explicit))

        assert ips == {'192.0.2.1'}


class TestLoadIsAnnounced:
    """A file picked up without being asked for should say so"""

    def test_logged_when_writing_a_file(self, in_dir_with_default, caplog):
        """Not in --stdout or --dry-run, where output is the product"""
        with caplog.at_level(logging.INFO, logger='pfsense_redactor'):
            collect(stdout=False)

        assert 'default allow-list' in caplog.text

    def test_not_logged_in_stdout_mode(self, in_dir_with_default, caplog):
        """stdout carries the redacted config, so nothing else may land there"""
        with caplog.at_level(logging.INFO, logger='pfsense_redactor'):
            collect(stdout=True)

        assert 'default allow-list' not in caplog.text
