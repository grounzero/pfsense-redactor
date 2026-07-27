"""Version consistency tests

The version is declared in two places that must agree: pyproject.toml (what
PyPI publishes) and pfsense_redactor.__version__ (what --version reports, and
what is stamped into the redaction comment in every output file).

These are checked rather than generated because drift is silent and has already
happened once: a hardcoded fallback in redactor.py sat two releases behind
before it was noticed. A release script only helps if it is remembered; a test
fails regardless of how the bump was made.
"""
import re
from pathlib import Path

import pfsense_redactor


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
CHANGELOG = PROJECT_ROOT / "CHANGELOG.md"

SEMVER_RE = re.compile(r'^\d+\.\d+\.\d+$')


def _pyproject_version():
    """Read version from pyproject.toml without requiring a TOML parser

    tomllib is 3.11+ and this project supports 3.9, so match the [project]
    version line directly.
    """
    content = PYPROJECT.read_text(encoding='utf-8')
    match = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
    assert match, "No version found in pyproject.toml"
    return match.group(1)


class TestVersionConsistency:
    """The declared version must agree across every place it appears"""

    def test_package_version_matches_pyproject(self):
        """__version__ and pyproject.toml must not drift apart"""
        assert pfsense_redactor.__version__ == _pyproject_version(), (
            "Version mismatch: pfsense_redactor.__version__ is "
            f"{pfsense_redactor.__version__!r} but pyproject.toml declares "
            f"{_pyproject_version()!r}. Update both."
        )

    def test_version_is_semver(self):
        """Version must be a plain three-part semantic version"""
        assert SEMVER_RE.match(pfsense_redactor.__version__), (
            f"Version {pfsense_redactor.__version__!r} is not MAJOR.MINOR.PATCH"
        )

    def test_no_stale_hardcoded_version_literals(self):
        """Source must not hardcode a version string that can go stale

        redactor.py previously carried a '1.0.8' fallback that drifted two
        releases behind. Fallbacks should report 'unknown' rather than a
        version that may be wrong.
        """
        source = (PROJECT_ROOT / "pfsense_redactor" / "redactor.py").read_text(encoding='utf-8')
        literals = re.findall(r'__version__\s*=\s*["\'](\d+\.\d+\.\d+)["\']', source)

        assert not literals, (
            f"redactor.py hardcodes version literal(s) {literals}. "
            "Use 'unknown' for fallbacks so they cannot go stale."
        )


class TestChangelogRelease:
    """The current version must be documented before it ships"""

    def test_changelog_has_entry_for_current_version(self):
        """Every released version needs a CHANGELOG heading"""
        content = CHANGELOG.read_text(encoding='utf-8')
        version = pfsense_redactor.__version__

        assert re.search(rf'^## \[{re.escape(version)}\]', content, re.MULTILINE), (
            f"CHANGELOG.md has no '## [{version}]' heading"
        )

    def test_changelog_has_link_reference_for_current_version(self):
        """Headings use reference-style links, so the target must exist"""
        content = CHANGELOG.read_text(encoding='utf-8')
        version = pfsense_redactor.__version__

        assert re.search(rf'^\[{re.escape(version)}\]:\s*https?://', content, re.MULTILINE), (
            f"CHANGELOG.md has no link reference for [{version}]"
        )

    def test_no_unreleased_section_left_open(self):
        """An open [Unreleased] section means the release was not closed out"""
        content = CHANGELOG.read_text(encoding='utf-8')

        assert not re.search(r'^## \[Unreleased\]', content, re.MULTILINE), (
            "CHANGELOG.md still has an open [Unreleased] section; "
            "rename it to the version being released"
        )


class TestRedactionCommentVersion:
    """Output files are stamped with the version, so it must be correct"""

    def test_output_comment_carries_current_version(self, create_xml_file, tmp_path, cli_runner):
        """The redaction comment must name the real version, not 'unknown'"""
        xml_file = create_xml_file('<?xml version="1.0"?><pfsense><version>1.0</version></pfsense>')
        output_file = tmp_path / "out.xml"

        exit_code, _, _ = cli_runner.run(str(xml_file), str(output_file))

        assert exit_code == 0
        assert f"v{pfsense_redactor.__version__}" in output_file.read_text(encoding='utf-8')
