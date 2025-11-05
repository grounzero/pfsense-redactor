"""
Tests for symlink security in --inplace mode

These tests verify that the tool refuses to follow symlinks when using --inplace,
preventing potential security issues where an attacker could replace a file with
a symlink to a sensitive system file.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import pytest


# Sample minimal pfSense config for testing
# Use testdomain.local instead of example.com (which is the default redaction value)
MINIMAL_PFSENSE_CONFIG = """<?xml version="1.0"?>
<pfsense>
    <version>1.0</version>
    <system>
        <hostname>test</hostname>
        <domain>testdomain.local</domain>
    </system>
</pfsense>
"""


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_config(temp_dir):
    """Create a sample pfSense config file"""
    config_path = temp_dir / "config.xml"
    config_path.write_text(MINIMAL_PFSENSE_CONFIG, encoding='utf-8')
    return config_path


def run_redactor(args, cwd=None):
    """Run the redactor with given arguments and return result"""
    cmd = [sys.executable, "-m", "pfsense_redactor"] + args
    # Don't change cwd - it can cause module resolution issues
    # The file paths are absolute anyway
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False
    )
    return result


class TestSymlinkSecurity:
    """Test symlink security in --inplace mode"""

    def test_regular_file_inplace(self, sample_config, temp_dir):
        """Test 1: Regular file with --inplace should work"""
        # Get original content
        original_content = sample_config.read_text(encoding='utf-8')

        # Run redactor with --inplace
        result = run_redactor(
            [str(sample_config), "--inplace", "--force"]
        )

        # Should succeed
        assert result.returncode == 0, f"Failed with stderr: {result.stderr}"

        # File should be modified
        modified_content = sample_config.read_text(encoding='utf-8')
        assert modified_content != original_content, "File should be modified"
        assert "testdomain.local" not in modified_content, "Domain should be redacted"

        # File should still exist and be a regular file
        assert sample_config.exists()
        assert not sample_config.is_symlink()

    def test_symlink_inplace_refused(self, sample_config, temp_dir):
        """Test 2: Symlink with --inplace should be refused"""
        # Create a symlink to the config
        symlink_path = temp_dir / "symlink.xml"
        symlink_path.symlink_to(sample_config)

        # Get original content
        original_content = sample_config.read_text(encoding='utf-8')

        # Try to run redactor on the symlink with --inplace
        result = run_redactor(
            [str(symlink_path), "--inplace", "--force"]
        )

        # Should fail
        assert result.returncode == 1, "Should exit with error code 1"

        # Error message should mention symlink
        assert "symlink" in result.stderr.lower(), f"Error should mention symlink: {result.stderr}"
        assert str(symlink_path.name) in result.stderr, f"Error should mention the symlink file: {result.stderr}"

        # Original file should NOT be modified
        current_content = sample_config.read_text(encoding='utf-8')
        assert current_content == original_content, "Original file should not be modified"

    def test_symlink_to_sensitive_file_refused(self, temp_dir):
        """Test 3: Symlink to sensitive file should be refused"""
        # Create a test target file in temp directory (simulating sensitive file)
        target_path = temp_dir / "sensitive-target.xml"
        target_path.write_text(MINIMAL_PFSENSE_CONFIG, encoding='utf-8')

        # Create symlink in current directory pointing to target
        symlink_path = temp_dir / "config.xml"
        symlink_path.symlink_to(target_path)

        # Get original content
        original_content = target_path.read_text(encoding='utf-8')

        # Try to run redactor on the symlink
        result = run_redactor(
            [str(symlink_path), "--inplace", "--force"],
            cwd=temp_dir
        )

        # Should fail
        assert result.returncode == 1, "Should exit with error code 1"

        # Error should mention symlink and show target
        assert "symlink" in result.stderr.lower(), f"Error should mention symlink: {result.stderr}"
        assert "target" in result.stderr.lower() or str(target_path) in result.stderr, \
            f"Error should show symlink target: {result.stderr}"

        # Target file should NOT be modified
        current_content = target_path.read_text(encoding='utf-8')
        assert current_content == original_content, "Target file should not be modified"

    @pytest.mark.skipif(os.name == 'nt', reason="Hardlinks work differently on Windows")
    def test_hardlink_inplace_allowed(self, sample_config, temp_dir):
        """Test 4: Hardlink with --inplace should work (different from symlink)"""
        # Create a hardlink to the config
        hardlink_path = temp_dir / "hardlink.xml"
        os.link(sample_config, hardlink_path)

        # Get original content
        original_content = sample_config.read_text(encoding='utf-8')

        # Run redactor on the hardlink with --inplace
        result = run_redactor(
            [str(hardlink_path), "--inplace", "--force"]
        )

        # Should succeed (hardlinks are safe)
        assert result.returncode == 0, f"Hardlink should be allowed: {result.stderr}"

        # Both names should point to the same modified content
        hardlink_content = hardlink_path.read_text(encoding='utf-8')
        original_content_now = sample_config.read_text(encoding='utf-8')

        assert hardlink_content == original_content_now, "Both hardlinks should have same content"
        assert hardlink_content != original_content, "Content should be modified"
        assert "testdomain.local" not in hardlink_content, "Domain should be redacted"

    def test_nested_symlinks_refused(self, sample_config, temp_dir):
        """Test 5: Nested symlinks (symlink to symlink) should be refused"""
        # Create first symlink to the config
        symlink1_path = temp_dir / "symlink1.xml"
        symlink1_path.symlink_to(sample_config)

        # Create second symlink pointing to first symlink
        symlink2_path = temp_dir / "symlink2.xml"
        symlink2_path.symlink_to(symlink1_path)

        # Get original content
        original_content = sample_config.read_text(encoding='utf-8')

        # Try to run redactor on the second symlink
        result = run_redactor(
            [str(symlink2_path), "--inplace", "--force"]
        )

        # Should fail (symlink2 is itself a symlink)
        assert result.returncode == 1, "Should exit with error code 1"

        # Error should mention symlink
        assert "symlink" in result.stderr.lower(), f"Error should mention symlink: {result.stderr}"

        # Original file should NOT be modified
        current_content = sample_config.read_text(encoding='utf-8')
        assert current_content == original_content, "Original file should not be modified"

    def test_broken_symlink_refused(self, temp_dir):
        """Test 6: Broken symlink (pointing to non-existent file) should be refused"""
        # Create a symlink to a non-existent file
        non_existent = temp_dir / "does-not-exist.xml"
        symlink_path = temp_dir / "broken-symlink.xml"
        symlink_path.symlink_to(non_existent)

        # Try to run redactor on the broken symlink
        result = run_redactor(
            [str(symlink_path), "--inplace", "--force"]
        )

        # Should fail (either due to symlink check or file not found)
        assert result.returncode == 1, "Should exit with error code 1"

        # Error should mention either symlink or file not found
        stderr_lower = result.stderr.lower()
        assert "symlink" in stderr_lower or "not found" in stderr_lower, \
            f"Error should mention symlink or file not found: {result.stderr}"

    def test_symlink_to_directory_refused(self, temp_dir):
        """Test 7: Symlink to directory should be refused"""
        # Create a subdirectory
        subdir = temp_dir / "subdir"
        subdir.mkdir()

        # Create a symlink to the directory
        symlink_path = temp_dir / "dir-symlink"
        symlink_path.symlink_to(subdir)

        # Try to run redactor on the directory symlink
        result = run_redactor(
            [str(symlink_path), "--inplace", "--force"]
        )

        # Should fail
        assert result.returncode == 1, "Should exit with error code 1"

        # Error should mention symlink or that it's not a file
        stderr_lower = result.stderr.lower()
        assert "symlink" in stderr_lower or "not found" in stderr_lower or "directory" in stderr_lower, \
            f"Error should mention issue: {result.stderr}"

    def test_relative_symlink_refused(self, sample_config, temp_dir):
        """Test 8: Relative symlink should also be refused"""
        # Create a relative symlink
        symlink_path = temp_dir / "relative-symlink.xml"
        # Use relative path
        symlink_path.symlink_to(sample_config.name)

        # Get original content
        original_content = sample_config.read_text(encoding='utf-8')

        # Try to run redactor on the relative symlink
        result = run_redactor(
            [str(symlink_path), "--inplace", "--force"]
        )

        # Should fail
        assert result.returncode == 1, "Should exit with error code 1"

        # Error should mention symlink
        assert "symlink" in result.stderr.lower(), f"Error should mention symlink: {result.stderr}"

        # Original file should NOT be modified
        current_content = sample_config.read_text(encoding='utf-8')
        assert current_content == original_content, "Original file should not be modified"

    def test_symlink_without_inplace_works(self, sample_config, temp_dir):
        """Test 9: Symlink should work fine WITHOUT --inplace (reading is safe)"""
        # Create a symlink to the config
        symlink_path = temp_dir / "symlink.xml"
        symlink_path.symlink_to(sample_config)

        # Create output file
        output_path = temp_dir / "output.xml"

        # Run redactor WITHOUT --inplace (reading through symlink is safe)
        result = run_redactor(
            [str(symlink_path), str(output_path), "--force"]
        )

        # Should succeed (reading through symlinks is safe)
        assert result.returncode == 0, f"Reading through symlink should work: {result.stderr}"

        # Output file should exist and contain redacted content
        assert output_path.exists()
        output_content = output_path.read_text(encoding='utf-8')
        assert "testdomain.local" not in output_content, "Domain should be redacted in output"

    @pytest.mark.skipif(os.name == 'nt', reason="Windows symlinks require admin privileges")
    def test_error_message_shows_target(self, sample_config, temp_dir):
        """Test 10: Error message should show the symlink target for clarity"""
        # Create a symlink
        symlink_path = temp_dir / "link.xml"
        symlink_path.symlink_to(sample_config)

        # Try to run redactor on the symlink
        result = run_redactor(
            [str(symlink_path), "--inplace", "--force"]
        )

        # Should fail
        assert result.returncode == 1

        # Error message should include both the symlink name and target
        assert str(symlink_path.name) in result.stderr, "Error should mention symlink name"
        assert "target" in result.stderr.lower(), "Error should mention 'target'"
        # The target path should be shown (either absolute or relative)
        assert str(sample_config.name) in result.stderr or str(sample_config) in result.stderr, \
            f"Error should show target path: {result.stderr}"
