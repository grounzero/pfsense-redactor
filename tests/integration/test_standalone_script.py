"""Standalone single-file execution tests

redactor.py must remain runnable as a lone file, with no package context and
nothing else beside it. This is the reason the module is not split up despite
its size (see the module docstring in redactor.py and the C0302 disable in
.pylintrc), so it needs a test rather than being an undocumented accident.

The existing CLIRunner also invokes redactor.py as a script, but from the repo
root where the rest of the package and pyproject.toml sit alongside it -- that
would not catch a sibling-module import. These tests copy the file out on its
own first.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REDACTOR_SOURCE = PROJECT_ROOT / "pfsense_redactor" / "redactor.py"

MINIMAL_CONFIG = (
    '<?xml version="1.0"?>'
    '<pfsense><system>'
    '<password>SUPERSECRET</password>'
    '<hostname>fw-test</hostname>'
    '</system></pfsense>'
)


@pytest.fixture
def lone_script(tmp_path):
    """Copy redactor.py into an otherwise empty directory

    No __init__.py, no sibling modules, no pyproject.toml - so any relative or
    sibling import in redactor.py will fail here.
    """
    isolated = tmp_path / "isolated"
    isolated.mkdir()
    target = isolated / "redactor.py"
    shutil.copy2(REDACTOR_SOURCE, target)
    return target


class TestStandaloneExecution:
    """redactor.py works with no package context"""

    def test_redacts_when_run_as_lone_file(self, lone_script, tmp_path):
        """The core promise: copy one file out, run it, get a redacted config"""
        config = tmp_path / "config.xml"
        config.write_text(MINIMAL_CONFIG, encoding='utf-8')

        result = subprocess.run(
            [sys.executable, str(lone_script), str(config), "--stdout"],
            capture_output=True,
            text=True,
            cwd=str(lone_script.parent),
            check=False,
        )

        assert result.returncode == 0, (
            f"redactor.py failed to run standalone.\nstderr:\n{result.stderr}"
        )
        assert '[REDACTED]' in result.stdout
        assert 'SUPERSECRET' not in result.stdout

    def test_no_import_error_on_lone_file(self, lone_script, tmp_path):
        """A sibling or relative import would surface as ImportError here

        Asserted separately from the redaction check so that a future split
        fails with a message naming the cause rather than a generic non-zero
        exit.
        """
        config = tmp_path / "config.xml"
        config.write_text(MINIMAL_CONFIG, encoding='utf-8')

        result = subprocess.run(
            [sys.executable, str(lone_script), str(config), "--stdout"],
            capture_output=True,
            text=True,
            cwd=str(lone_script.parent),
            check=False,
        )

        for marker in ('ImportError', 'ModuleNotFoundError', 'attempted relative import'):
            assert marker not in result.stderr, (
                f"redactor.py is no longer self-contained ({marker}). It must stay "
                "runnable as a single file; see its module docstring.\n"
                f"stderr:\n{result.stderr}"
            )

    def test_version_flag_degrades_gracefully(self, lone_script):
        """Without pyproject.toml alongside, --version reports 'unknown'

        resolve_version() deliberately reports 'unknown' rather than a
        hardcoded literal that could go stale. Standalone use is exactly the
        case where neither the package import nor pyproject.toml is available,
        so it must not crash.
        """
        result = subprocess.run(
            [sys.executable, str(lone_script), "--version"],
            capture_output=True,
            text=True,
            cwd=str(lone_script.parent),
            check=False,
        )

        assert result.returncode == 0
        assert result.stdout.strip(), "expected some version output"
