"""File identity and the atomic writer, tested directly

tests/adversarial/test_filesystem_safety.py drives these through the CLI, which
is where the behaviour matters. This file tests the two primitives on their own,
because they are small, security-critical and cheap to get subtly wrong: an
identity check that compares strings, or a "safe" write that fsyncs after the
rename instead of before it, both look correct and are not.

POSIX-specific behaviour is skipped rather than asserted on Windows, where file
permissions are ACLs and st_nlink means something different.
"""
import os
import stat

import pytest

from pfsense_redactor.redactor import (
    OUTPUT_FILE_MODE,
    TEMP_OUTPUT_PREFIX,
    inplace_path_refusal,
    output_path_refusal,
    paths_identify_same_file,
    write_bytes_atomically,
)

PAYLOAD = b"<?xml version='1.0' encoding='utf-8'?>\n<pfsense><a>b</a></pfsense>"
POSIX_ONLY = pytest.mark.skipif(os.name == "nt", reason="POSIX semantics")


@pytest.fixture
def source(tmp_path):
    """A file standing in for the operator's configuration"""
    path = tmp_path / "config.xml"
    path.write_bytes(b"<pfsense><password>SECRET</password></pfsense>")
    return path


class TestPathIdentity:
    """Two names reach the same file, or they do not. Strings cannot say."""

    def test_identical_paths(self, source):
        """The obvious case"""
        assert paths_identify_same_file(str(source), str(source))

    def test_relative_alias(self, source, monkeypatch):
        """'config.xml' and './config.xml' are one file"""
        monkeypatch.chdir(source.parent)
        assert paths_identify_same_file("config.xml", "./config.xml")

    def test_dot_dot_alias(self, source, monkeypatch):
        """So are 'config.xml' and 'sub/../config.xml'"""
        (source.parent / "sub").mkdir()
        monkeypatch.chdir(source.parent)
        assert paths_identify_same_file("config.xml", "sub/../config.xml")

    @POSIX_ONLY
    def test_symlink_alias(self, source, tmp_path):
        """A symlink reaches the file it points at"""
        link = tmp_path / "link.xml"
        link.symlink_to(source)
        assert paths_identify_same_file(str(source), str(link))

    @POSIX_ONLY
    def test_hardlink_alias(self, source, tmp_path):
        """So does a hard link, which no path comparison would notice"""
        alias = tmp_path / "alias.xml"
        os.link(source, alias)
        assert paths_identify_same_file(str(source), str(alias))

    def test_different_files(self, source, tmp_path):
        """The control"""
        other = tmp_path / "other.xml"
        other.write_bytes(b"<pfsense/>")
        assert not paths_identify_same_file(str(source), str(other))

    def test_a_path_that_does_not_exist_yet(self, source, tmp_path):
        """The output usually does not exist, and that is not a match"""
        assert not paths_identify_same_file(str(source), str(tmp_path / "new.xml"))

    def test_neither_path_exists(self, tmp_path):
        """Falls back to resolved-path comparison without raising"""
        assert paths_identify_same_file(str(tmp_path / "a"), str(tmp_path / "a"))
        assert not paths_identify_same_file(str(tmp_path / "a"), str(tmp_path / "b"))


class TestOutputRefusal:
    """Which destinations are refused, and for which stated reason"""

    def test_the_input_itself_is_refused(self, source):
        """--inplace by accident, without --inplace's guards"""
        refusal = output_path_refusal(str(source), str(source))
        assert refusal is not None
        assert "input file" in refusal

    def test_a_relative_alias_of_the_input_is_refused(self, source, monkeypatch):
        """Spelling it differently is not a different file"""
        monkeypatch.chdir(source.parent)
        assert output_path_refusal("config.xml", "./config.xml") is not None

    @POSIX_ONLY
    def test_a_symlink_destination_is_refused(self, source, tmp_path):
        """Writing would follow it somewhere the operator did not name"""
        other = tmp_path / "other.xml"
        other.write_bytes(b"<pfsense/>")
        link = tmp_path / "link.xml"
        link.symlink_to(other)

        refusal = output_path_refusal(str(source), str(link))
        assert refusal is not None
        assert "symbolic link" in refusal

    @POSIX_ONLY
    def test_a_hardlinked_destination_is_refused(self, source, tmp_path):
        """Atomic replacement would leave the other name holding stale content"""
        target = tmp_path / "out.xml"
        target.write_bytes(b"<pfsense/>")
        os.link(target, tmp_path / "alias.xml")

        refusal = output_path_refusal(str(source), str(target))
        assert refusal is not None
        assert "hard link" in refusal

    def test_an_ordinary_new_destination_is_accepted(self, source, tmp_path):
        """The control: a refusal that refuses everything protects nothing"""
        assert output_path_refusal(str(source), str(tmp_path / "out.xml")) is None

    def test_an_ordinary_existing_destination_is_accepted(self, source, tmp_path):
        """Overwriting a single-named file is what --force is for"""
        target = tmp_path / "out.xml"
        target.write_bytes(b"<pfsense/>")
        assert output_path_refusal(str(source), str(target)) is None

    @POSIX_ONLY
    def test_inplace_on_a_hardlink_is_refused(self, source, tmp_path):
        """The other name would keep the unredacted configuration"""
        os.link(source, tmp_path / "alias.xml")

        refusal = inplace_path_refusal(str(source))
        assert refusal is not None
        assert "hard link" in refusal

    def test_inplace_on_an_ordinary_file_is_accepted(self, source):
        """The control"""
        assert inplace_path_refusal(str(source)) is None


class TestAtomicWrite:
    """Either the previous content or the complete new content. Never both."""

    def test_writes_the_payload(self, tmp_path):
        """The ordinary case"""
        target = tmp_path / "out.xml"
        write_bytes_atomically(str(target), PAYLOAD)
        assert target.read_bytes() == PAYLOAD

    def test_replaces_existing_content_completely(self, tmp_path):
        """No remnant of a longer previous file survives"""
        target = tmp_path / "out.xml"
        target.write_bytes(b"X" * (len(PAYLOAD) * 4))
        write_bytes_atomically(str(target), PAYLOAD)
        assert target.read_bytes() == PAYLOAD

    @POSIX_ONLY
    def test_creates_the_file_at_0600(self, tmp_path):
        """Redacted output can still hold retained values and topology"""
        target = tmp_path / "out.xml"
        write_bytes_atomically(str(target), PAYLOAD)

        assert stat.S_IMODE(target.stat().st_mode) == OUTPUT_FILE_MODE

    @POSIX_ONLY
    def test_is_not_world_readable_whatever_the_umask(self, tmp_path):
        """The permissive-umask case is the one that matters"""
        previous = os.umask(0o000)
        try:
            target = tmp_path / "out.xml"
            write_bytes_atomically(str(target), PAYLOAD)
        finally:
            os.umask(previous)

        mode = stat.S_IMODE(target.stat().st_mode)
        assert not mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH)

    def test_leaves_no_temporary_file(self, tmp_path):
        """The destination directory is clean afterwards"""
        write_bytes_atomically(str(tmp_path / "out.xml"), PAYLOAD)

        assert {p.name for p in tmp_path.iterdir()} == {"out.xml"}

    @pytest.mark.parametrize("step", ["fsync", "replace", "chmod"])
    def test_a_failure_leaves_the_destination_untouched(self, tmp_path, monkeypatch, step):
        """Every step that can fail, and the same guarantee for each"""
        target = tmp_path / "out.xml"
        target.write_bytes(b"<pfsense><previous/></pfsense>")
        before = target.read_bytes()

        def explode(*args, **kwargs):
            raise OSError(f"simulated failure in os.{step}")

        monkeypatch.setattr(f"os.{step}", explode)

        with pytest.raises(OSError):
            write_bytes_atomically(str(target), PAYLOAD)

        assert target.read_bytes() == before

    @pytest.mark.parametrize("step", ["fsync", "replace", "chmod"])
    def test_a_failure_leaves_no_temporary_file(self, tmp_path, monkeypatch, step):
        """Cleanup runs on the failure path, not only the happy one"""
        target = tmp_path / "out.xml"

        def explode(*args, **kwargs):
            raise OSError(f"simulated failure in os.{step}")

        monkeypatch.setattr(f"os.{step}", explode)

        with pytest.raises(OSError):
            write_bytes_atomically(str(target), PAYLOAD)

        assert not list(tmp_path.glob(f"{TEMP_OUTPUT_PREFIX}*"))
        assert not target.exists()

    def test_an_interrupt_is_cleaned_up_and_re_raised(self, tmp_path, monkeypatch):
        """A SIGINT mid-write is the case the operator actually hits"""
        target = tmp_path / "out.xml"

        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt

        monkeypatch.setattr("os.replace", interrupt)

        with pytest.raises(KeyboardInterrupt):
            write_bytes_atomically(str(target), PAYLOAD)

        assert not list(tmp_path.glob(f"{TEMP_OUTPUT_PREFIX}*"))
        assert not target.exists()

    def test_the_temporary_file_is_in_the_destination_directory(self, tmp_path, monkeypatch):
        """Cross-filesystem renames are not atomic, so the temp file must be local

        Asserted by capturing where mkstemp is asked to put it, because by the
        time the write returns the evidence has been renamed away.
        """
        seen = {}
        real_mkstemp = __import__('tempfile').mkstemp

        def recording_mkstemp(*args, **kwargs):
            seen['dir'] = kwargs.get('dir')
            return real_mkstemp(*args, **kwargs)

        monkeypatch.setattr("tempfile.mkstemp", recording_mkstemp)

        target = tmp_path / "sub" / "out.xml"
        target.parent.mkdir()
        write_bytes_atomically(str(target), PAYLOAD)

        assert seen['dir'] == str(target.parent)

    @POSIX_ONLY
    def test_the_temporary_file_is_never_world_readable(self, tmp_path, monkeypatch):
        """The window before the rename must not expose the content either"""
        observed = {}
        target = tmp_path / "out.xml"
        real_replace = os.replace

        def inspect_then_replace(src, dst, *args, **kwargs):
            observed['mode'] = stat.S_IMODE(os.stat(src).st_mode)
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr("os.replace", inspect_then_replace)

        previous = os.umask(0o000)
        try:
            write_bytes_atomically(str(target), PAYLOAD)
        finally:
            os.umask(previous)

        assert observed['mode'] == OUTPUT_FILE_MODE
