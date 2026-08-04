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

    def test_same_input_and_output_path_is_refused(self, canary_copy, run_redactor):
        """Naming the input as the output must not destroy it"""
        before = canary_copy.read_bytes()
        result = run_redactor(canary_copy, canary_copy, "--force")

        assert result.returncode != 0
        assert canary_copy.read_bytes() == before

    def test_same_file_via_relative_indirection_is_refused(self, canary_copy, run_redactor):
        """Spelling the path differently must not defeat the check"""
        before = canary_copy.read_bytes()
        result = run_redactor("config.xml", "./config.xml", "--force", cwd=canary_copy.parent)

        assert result.returncode != 0
        assert canary_copy.read_bytes() == before

    def test_output_symlink_pointing_at_input_is_refused(self, canary_copy, run_redactor, tmp_path):
        """Nor must reaching the input through a link"""
        link = tmp_path / "out-link.xml"
        link.symlink_to(canary_copy)
        before = canary_copy.read_bytes()

        result = run_redactor(canary_copy, link, "--force")

        assert result.returncode != 0 or canary_copy.read_bytes() == before

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


def fail_at(monkeypatch, name):
    """Make one step of the atomic write fail, the way a real one can

    The write is: temp file in the destination directory, fchmod, write, flush,
    fsync, close, os.replace, fsync the directory. A crash can land at any of
    them - disk full at the write, SIGINT before the rename, power loss after
    it - and the guarantee is the same in every case: the destination holds
    either its previous content or the complete new content, and no temporary
    file survives.
    """
    def explode(*args, **kwargs):
        raise OSError(f"simulated failure in {name}")

    monkeypatch.setattr(f"os.{name}", explode)


class TestWriteSafety:
    """How the output is written, not where"""

    @pytest.mark.skipif(
        os.name == "nt",
        reason="POSIX mode bits only: Windows permissions are ACLs, os.stat "
               "reports 0666 for any writable file whatever the ACL says, and "
               "os.chmod can only clear the read-only bit. The 0600 guarantee "
               "is POSIX-only and documented as such in docs/security.md",
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

    @pytest.mark.parametrize("step", ["fsync", "replace"])
    def test_interrupted_inplace_write_preserves_the_original(
        self, canary_copy, monkeypatch, step
    ):
        """A crash mid-write must not leave the operator with nothing

        Reproduced before the fix at 7889 bytes -> 36: tree.write() opened the
        target, truncating it, and only then began serialising.
        """
        before = canary_copy.read_bytes()
        fail_at(monkeypatch, step)

        redactor = PfSenseRedactor()
        assert redactor.redact_config(str(canary_copy), str(canary_copy), inplace=True) is False
        assert canary_copy.read_bytes() == before, (
            f"original truncated to {canary_copy.stat().st_size} bytes "
            f"from {len(before)}"
        )

    @pytest.mark.parametrize("step", ["fsync", "replace"])
    def test_interrupted_write_leaves_no_partial_output(
        self, canary_copy, tmp_path, monkeypatch, step
    ):
        """A truncated file that looks like output is worse than none"""
        out = tmp_path / "out.xml"
        fail_at(monkeypatch, step)

        PfSenseRedactor().redact_config(str(canary_copy), str(out))

        assert not out.exists(), (
            "a truncated file that looks like output is worse than no output"
        )

    @pytest.mark.parametrize("step", ["fsync", "replace"])
    def test_interrupted_overwrite_preserves_the_existing_destination(
        self, canary_copy, tmp_path, monkeypatch, step
    ):
        """An existing destination survives a failed write byte-for-byte"""
        out = tmp_path / "out.xml"
        out.write_bytes(b"<pfsense><previous/></pfsense>")
        before = out.read_bytes()
        fail_at(monkeypatch, step)

        PfSenseRedactor().redact_config(str(canary_copy), str(out))

        assert out.read_bytes() == before

    @pytest.mark.parametrize("step", ["fsync", "replace"])
    def test_interrupted_write_leaves_no_temporary_file(
        self, canary_copy, tmp_path, monkeypatch, step
    ):
        """Cleanup runs on every failure path, not just the tidy ones"""
        out = tmp_path / "out.xml"
        fail_at(monkeypatch, step)

        PfSenseRedactor().redact_config(str(canary_copy), str(out))

        assert not list(tmp_path.glob(".pfsense-redactor-*"))

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

    @pytest.mark.skipif(os.name == "nt", reason="POSIX hard links only")
    def test_hardlinked_output_is_refused(self, canary_copy, run_redactor, tmp_path):
        """A hard-linked destination is refused rather than written through

        This test previously asserted the opposite - that writing over one name
        of a hard-linked file changed every name - and its own docstring named
        this as the place the atomic-write change would surface. It has.

        Atomic replacement puts a *new inode* at the destination, so the other
        name keeps pointing at the old content. For a file being redacted that
        old content is the unredacted configuration, now sitting under a name
        the operator has no reason to check. Writing through the link is not
        available any more, and silently stranding a stale copy is worse than
        refusing, so the destination is refused.

        The invariant is unchanged and is asserted below: after the run, no
        name holds content the operator believes was redacted but was not.
        """
        out = tmp_path / "out.xml"
        out.write_text("<pfsense><old/></pfsense>")
        alias = tmp_path / "alias.xml"
        os.link(out, alias)
        before = out.read_bytes()

        result = run_redactor(canary_copy, out, "--force")

        assert result.returncode != 0
        assert "hard link" in result.stderr.lower()
        assert out.read_bytes() == before, "the refused write happened anyway"
        assert Path(alias).read_bytes() == before
        assert out.stat().st_nlink == 2, "the link was broken despite the refusal"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX hard links only")
    def test_hardlinked_output_with_no_alias_is_allowed(self, canary_copy, run_redactor, tmp_path):
        """The control: an ordinary destination with one name still works"""
        out = tmp_path / "out.xml"
        out.write_text("<pfsense><old/></pfsense>")

        result = run_redactor(canary_copy, out, "--force")

        assert result.returncode == 0
        assert "<old/>" not in out.read_text()
