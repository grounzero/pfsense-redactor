"""Coverage startup hook for subprocesses.

Most CLI tests run redactor.py through subprocess (see CLIRunner in
tests/conftest.py). Python does not start coverage in a child process on its
own, so main(), redact_config() and the allow-list parsing were reported as
uncovered despite ~100 end-to-end runs exercising them - understating
redactor.py by roughly ten percentage points.

conftest.py puts this directory on PYTHONPATH and sets COVERAGE_PROCESS_START
for child processes, but only when the parent is itself running under
coverage. Python imports sitecustomize automatically at startup, which is what
gives coverage a chance to begin measuring before redactor.py is loaded.

process_startup() is a no-op unless COVERAGE_PROCESS_START is set, so this file
is harmless if it is ever imported outside a coverage run.
"""
try:
    import coverage
except ImportError:  # pragma: no cover - coverage not installed
    pass
else:  # pragma: no cover - runs in child processes, before measurement starts
    coverage.process_startup()
