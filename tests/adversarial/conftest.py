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
    """
    try:
        from tests.conftest import subprocess_env  # pylint: disable=import-outside-toplevel
    except ImportError:
        return os.environ.copy()
    return subprocess_env()


@pytest.fixture
def adversarial_canary() -> Path:
    """The adversarial corpus, which is expected to defeat several passes"""
    if not ADVERSARIAL_CANARY.exists():  # pragma: no cover - repo integrity
        pytest.skip(f"missing fixture: {ADVERSARIAL_CANARY}")
    return ADVERSARIAL_CANARY


@pytest.fixture
def run_redactor():
    """Run the CLI as a subprocess and return the CompletedProcess

    A thin wrapper rather than CLIRunner because these tests care about the
    exit code and the side effects on disk in cases where the run is *meant*
    to fail, which CLIRunner's expect_success default gets in the way of.
    """
    def _run(*args, cwd: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "pfsense_redactor", *[str(a) for a in args]],
            capture_output=True,
            text=True,
            cwd=str(cwd or PROJECT_ROOT),
            env=_subprocess_env(),
            check=False,
        )
    return _run


@pytest.fixture
def canary_copy(adversarial_canary, tmp_path) -> Path:
    """A writable copy of the adversarial corpus, for tests that mutate paths"""
    target = tmp_path / "config.xml"
    target.write_bytes(adversarial_canary.read_bytes())
    return target
