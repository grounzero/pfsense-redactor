"""Fixtures shared by the adversarial suite

Builds on tests/conftest.py rather than replacing it: cli_runner, script_path
and the tmp_path-based helpers all still apply here.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
ADVERSARIAL_CANARY = FIXTURES / "adversarial-canary.xml"


def _subprocess_env() -> dict[str, str]:
    """Child-process environment, with coverage enabled when it is available

    Defers to tests/conftest.py's version when it can be imported. CI runs
    pytest from inside tests/, where that import is not guaranteed, so the
    fallback keeps these tests runnable from either working directory - they
    just go uninstrumented.

    PROJECT_ROOT is put on PYTHONPATH either way. Several tests below run the
    CLI with cwd set to a temporary directory, and `python -m pfsense_redactor`
    finds the package from the current directory only when that directory is
    the repository root. Without this, a job that runs pytest without
    `pip install -e .` gets ModuleNotFoundError from every such run - which is
    worse than a plain failure, because a test asserting "this was refused"
    cannot tell a refusal from a subprocess that never started.
    """
    try:
        from tests.conftest import subprocess_env  # pylint: disable=import-outside-toplevel
        env = subprocess_env()
    except ImportError:
        env = os.environ.copy()

    existing = env.get("PYTHONPATH", "")
    root = str(PROJECT_ROOT)
    env["PYTHONPATH"] = f"{root}{os.pathsep}{existing}" if existing else root
    return env


@pytest.fixture
def adversarial_canary() -> Path:
    """The adversarial corpus, which is expected to defeat several passes"""
    if not ADVERSARIAL_CANARY.exists():  # pragma: no cover - repo integrity
        pytest.skip(f"missing fixture: {ADVERSARIAL_CANARY}")
    return ADVERSARIAL_CANARY


# Startup failures that produce a non-zero exit and an empty stdout without
# the tool having run at all.
_NEVER_STARTED = (
    "No module named pfsense_redactor",
    "ModuleNotFoundError",
)


@pytest.fixture
def run_redactor():
    """Run the CLI as a subprocess and return the CompletedProcess

    A thin wrapper rather than CLIRunner because these tests care about the
    exit code and the side effects on disk in cases where the run is *meant*
    to fail, which CLIRunner's expect_success default gets in the way of.

    A subprocess that never started is turned into an immediate test failure
    rather than being returned. Most tests here assert some combination of
    "non-zero exit" and "the file was not modified", and an interpreter that
    could not import the package satisfies both without executing a line of
    the code under test. That is the difference between a security test
    passing and a security test being *asked*, and it has to be loud.
    """
    def _run(*args, cwd: Path | None = None) -> subprocess.CompletedProcess:
        result = subprocess.run(
            [sys.executable, "-m", "pfsense_redactor", *[str(a) for a in args]],
            capture_output=True,
            text=True,
            cwd=str(cwd or PROJECT_ROOT),
            env=_subprocess_env(),
            check=False,
        )

        if any(marker in result.stderr for marker in _NEVER_STARTED):
            pytest.fail(
                "the redactor never started, so nothing below was actually "
                f"tested:\n{result.stderr.strip()[:800]}"
            )
        return result
    return _run


@pytest.fixture
def canary_copy(adversarial_canary, tmp_path) -> Path:
    """A writable copy of the adversarial corpus, for tests that mutate paths"""
    target = tmp_path / "config.xml"
    target.write_bytes(adversarial_canary.read_bytes())
    return target
