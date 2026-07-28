"""Phase 5: file-system safety

Path traversal, sensitive directories and --inplace-on-a-symlink are already
covered by tests/unit/test_path_validation.py, tests/unit/test_symlink_security.py
and tests/integration/test_path_security.py. This file covers what those do
not: whether the *write* is safe once the path has been accepted.

The threat is not an attacker on the box. It is an operator with one copy of a
firewall configuration, a tool they have been told is safe to point at it, and
a laptop that can run out of battery mid-write.
"""
from __future__ import annotations

import os
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from pfsense_redactor.redactor import PfSenseRedactor


class TestInputPreservation:
    """The input is the only copy of the secrets. It must survive."""

    def test_input_untouched_in_every_non_inplace_mode(self, canary_copy, run_redactor, tmp_path):
        """Only --inplace may ever alter the input"""
        before = canary_copy.read_bytes()
        for flags in (["--stdout"], ["--dry-run"], ["--dry-run-verbose"],
                      [str(tmp_path / "o1.xml")], ["--aggressive", "--stdout"]):
            run_redactor(canary_copy, *flags)
            assert canary_copy.read_bytes() == before, flags

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-15: input and output paths are never compared, so "
               "naming the input as the output destroys it",
    )
    def test_same_input_and_output_path_is_refused(self, canary_copy, run_redactor):
        """Naming the input as the output must not destroy it"""
        before = canary_copy.read_bytes()
        result = run_redactor(canary_copy, canary_copy, "--force")

        assert result.returncode != 0
        assert canary_copy.read_bytes() == before

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-15: the comparison is textual at best, so ./name and "
               "name reach the same file undetected",
    )
    def test_same_file_via_relative_indirection_is_refused(self, canary_copy, run_redactor):
        """Spelling the path differently must not defeat the check"""
        before = canary_copy.read_bytes()
        result = run_redactor("config.xml", "./config.xml", "--force", cwd=canary_copy.parent)

        assert result.returncode != 0
        assert canary_copy.read_bytes() == before

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-16: an output path that is a symlink is followed, so a "
               "link pointing back at the input overwrites the input",
    )
    def test_output_symlink_pointing_at_input_is_refused(self, canary_copy, run_redactor, tmp_path):
        """Nor must reaching the input through a link"""
        link = tmp_path / "out-link.xml"
        link.symlink_to(canary_copy)
        before = canary_copy.read_bytes()

        result = run_redactor(canary_copy, link, "--force")

        assert result.returncode != 0 or canary_copy.read_bytes() == before

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-17: --inplace rewrites the original without requiring "
               "--force; only args.output is covered by the overwrite guard",
    )
    def test_inplace_requires_explicit_consent(self, canary_copy, run_redactor):
        """Destroying the original is not a default-worthy action"""
        before = canary_copy.read_bytes()
        result = run_redactor(canary_copy, "--inplace")

        assert result.returncode != 0 or canary_copy.read_bytes() == before, (
            "--inplace destroyed the original with no --force and no prompt"
        )

    def test_inplace_with_force_does_rewrite(self, canary_copy, run_redactor):
        """The documented behaviour, pinned so a fix for the above is scoped"""
        before = canary_copy.read_bytes()
        run_redactor(canary_copy, "--inplace", "--force")
        assert canary_copy.read_bytes() != before
        ET.fromstring(canary_copy.read_text())


class TestWriteSafety:
    """How the output is written, not where"""

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-18: tree.write() creates the file with the process "
               "umask, so redacted output is typically world-readable 0644",
    )
    def test_output_is_not_world_readable(self, canary_copy, run_redactor, tmp_path):
        """Redacted output can still hold retained values"""
        out = tmp_path / "out.xml"
        run_redactor(canary_copy, out)

        mode = stat.S_IMODE(out.stat().st_mode)
        assert not mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH), (
            f"mode {mode:04o}; redacted output can still hold retained "
            f"high-entropy values and identifying material"
        )

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-19: the write is not atomic - tree.write() truncates "
               "the target first, so a failure mid-write destroys it",
    )
    def test_interrupted_inplace_write_preserves_the_original(self, canary_copy, monkeypatch):
        """A crash mid-write must not leave the operator with nothing"""
        before = canary_copy.read_bytes()

        def explode(self, file_or_filename, **kwargs):  # pylint: disable=unused-argument
            # Emulate a crash after the target has been opened for writing,
            # which is what tree.write() does before it can fail.
            if not hasattr(file_or_filename, "write"):
                with open(file_or_filename, "wb") as handle:
                    handle.write(b'<?xml version="1.0"?>\n<pfsense><syst')
            raise OSError("simulated I/O failure mid-write")

        monkeypatch.setattr(ET.ElementTree, "write", explode)

        redactor = PfSenseRedactor()
        assert redactor.redact_config(str(canary_copy), str(canary_copy), inplace=True) is False
        assert canary_copy.read_bytes() == before, (
            f"original truncated to {canary_copy.stat().st_size} bytes "
            f"from {len(before)}"
        )

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-19: a failed write leaves the partial file behind "
               "rather than removing it",
    )
    def test_interrupted_write_leaves_no_partial_output(self, canary_copy, tmp_path, monkeypatch):
        """A truncated file that looks like output is worse than none"""
        out = tmp_path / "out.xml"

        def explode(self, file_or_filename, **kwargs):  # pylint: disable=unused-argument
            if not hasattr(file_or_filename, "write"):
                with open(file_or_filename, "wb") as handle:
                    handle.write(b'<?xml version="1.0"?>\n<pfsense><syst')
            raise OSError("simulated I/O failure mid-write")

        monkeypatch.setattr(ET.ElementTree, "write", explode)

        PfSenseRedactor().redact_config(str(canary_copy), str(out))

        assert not out.exists(), (
            "a truncated file that looks like output is worse than no output"
        )

    def test_no_temporary_files_are_left_behind(self, canary_copy, run_redactor, tmp_path):
        """Whatever the write strategy, the directory must be clean afterwards"""
        out = tmp_path / "out.xml"
        run_redactor(canary_copy, out)

        leftovers = {p.name for p in tmp_path.iterdir()} - {"config.xml", "out.xml"}
        assert not leftovers, leftovers


class TestSpecialFiles:
    """Non-regular inputs must be diagnosed, not half-read"""

    def test_directory_as_input_is_diagnosed(self, tmp_path, run_redactor):
        """A directory is refused cleanly"""
        result = run_redactor(tmp_path, "--stdout")
        assert result.returncode != 0
        assert "Traceback" not in result.stderr

    @pytest.mark.skipif(os.name == "nt", reason="POSIX FIFOs only")
    def test_fifo_as_input_is_diagnosed(self, tmp_path, run_redactor):
        """So is a FIFO"""
        fifo = tmp_path / "fifo.xml"
        os.mkfifo(fifo)
        result = run_redactor(fifo, "--stdout")
        assert result.returncode != 0
        assert "Traceback" not in result.stderr

    @pytest.mark.xfail(
        strict=True,
        reason="FINDING-20: the input is accepted on stat().st_size alone; "
               "there is no is_file() check, so a FIFO is diagnosed as 'empty' "
               "rather than as the wrong kind of file",
    )
    @pytest.mark.skipif(os.name == "nt", reason="POSIX FIFOs only")
    def test_fifo_is_diagnosed_as_a_non_regular_file(self, tmp_path, run_redactor):
        """And the diagnosis names the real problem"""
        fifo = tmp_path / "fifo.xml"
        os.mkfifo(fifo)
        result = run_redactor(fifo, "--stdout")
        assert "empty" not in result.stderr.lower(), (
            "a FIFO is not an empty file, and saying so sends the operator "
            "looking for the wrong problem"
        )

    def test_hardlinked_output_write_is_in_place(self, canary_copy, run_redactor, tmp_path):
        """Writing over one name of a hard-linked file changes every name

        tests/unit/test_symlink_security.py:139 documents --inplace on a hard
        link. This pins the *output* side, and it matters to whoever implements
        FINDING-19: an atomic temp-file-plus-rename write would break the link
        instead, leaving the alias holding the unredacted content. That is a
        behaviour change, and this test is where it will surface.
        """
        out = tmp_path / "out.xml"
        out.write_text("<pfsense><old/></pfsense>")
        alias = tmp_path / "alias.xml"
        os.link(out, alias)

        run_redactor(canary_copy, out, "--force")

        assert out.stat().st_nlink == 2, "the write broke the hard link"
        assert Path(alias).read_bytes() == out.read_bytes()
        assert "<old/>" not in alias.read_text()
