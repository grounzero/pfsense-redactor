"""The harness itself, because everything else in this directory trusts it

Most tests here assert some combination of "the run exited non-zero" and "the
file was not modified". An interpreter that could not import the package
satisfies both without executing a line of the code under test - so a broken
harness does not look like a broken harness, it looks like a passing security
suite.

That is not hypothetical. `python -m pfsense_redactor` resolves the package
from the current directory, and several tests here run the CLI with cwd set to
a temporary directory. In a CI job that ran pytest without `pip install -e .`,
every one of those runs failed to start:

    test_implicit_allowlist_changes_the_output   compared '' with ''
    test_no_default_allowlist_disables_it        compared '' with ''
    test_same_file_via_relative_indirection      XPASSed a strict xfail for
                                                 FINDING-15, which was not
                                                 fixed, because a crashed
                                                 subprocess is also a refusal

The third is the one that matters: a security test reporting success without
asking the question.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

from .conftest import PROJECT_ROOT, _subprocess_env


class TestTheHarnessCanRunTheTool:
    """The preconditions every other test in this directory depends on"""

    def test_the_package_is_importable_from_anywhere(self, tmp_path):
        """Not only from the repository root

        This is what fails when the package is not installed and the child
        process is started somewhere else.
        """
        result = subprocess.run(
            [sys.executable, "-c", "import pfsense_redactor"],
            capture_output=True, text=True, cwd=str(tmp_path),
            env=_subprocess_env(), check=False,
        )

        assert result.returncode == 0, result.stderr

    def test_the_project_root_is_on_the_child_pythonpath(self):
        """The mechanism, pinned so it is not removed as redundant"""
        assert str(PROJECT_ROOT) in _subprocess_env()["PYTHONPATH"].split(":")

    def test_a_run_from_a_temporary_directory_produces_output(self, tmp_path, run_redactor):
        """The end-to-end version of the two above"""
        config = tmp_path / "config.xml"
        config.write_text("<pfsense><system><hostname>fw</hostname></system></pfsense>")

        result = run_redactor("config.xml", "--stdout", cwd=tmp_path)

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip(), "no output from a run that should succeed"


class TestTheHarnessRefusesToPassSilently:
    """A subprocess that never started must not be mistaken for a refusal"""

    # What CPython actually prints when `-m pfsense_redactor` cannot resolve
    # the package. Reproduced as a literal because the package is installed in
    # any environment able to run this suite, so the condition cannot be
    # created for real here - only in the CI job that lacked the install.
    NEVER_STARTED_STDERR = (
        "/usr/bin/python3: Error while finding module specification for "
        "'pfsense_redactor' (ModuleNotFoundError: No module named "
        "'pfsense_redactor')\n"
    )

    def test_a_run_that_never_started_fails_the_test_rather_than_returning(
        self, tmp_path, run_redactor, monkeypatch
    ):
        """The guard, exercised

        A crashed subprocess exits non-zero and touches nothing, which is what
        a refusal also looks like. The harness must turn that into a loud
        failure rather than hand back a CompletedProcess the caller reads as a
        successful refusal.
        """
        def never_starts(*args, **kwargs):
            del args, kwargs
            return subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr=self.NEVER_STARTED_STDERR
            )

        monkeypatch.setattr(subprocess, "run", never_starts)

        with pytest.raises(pytest.fail.Exception, match="never started"):
            run_redactor("config.xml", "--stdout", cwd=tmp_path)

    def test_that_stderr_would_otherwise_have_looked_like_a_refusal(self, tmp_path):
        """Why the guard is needed, stated as an assertion

        Without it, the shape below satisfies both halves of what most tests
        in this directory check.
        """
        crashed = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr=self.NEVER_STARTED_STDERR
        )
        before = tmp_path / "config.xml"
        before.write_text("<pfsense/>")
        unchanged = before.read_bytes()

        assert crashed.returncode != 0            # "it was refused"
        assert before.read_bytes() == unchanged   # "and nothing was written"

    def test_the_guard_does_not_fire_on_an_ordinary_failure(self, tmp_path, run_redactor):
        """A real refusal still comes back as a result, not a test failure"""
        missing = tmp_path / "does-not-exist.xml"

        result = run_redactor(missing, "--stdout")

        assert result.returncode != 0
        assert "not found" in result.stderr.lower()
