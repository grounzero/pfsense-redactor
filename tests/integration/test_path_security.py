"""
Integration tests for file path security
Tests the CLI to ensure malicious paths are properly rejected
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

# Test data directory - use relative path to avoid absolute path issues
TEST_CONFIGS_DIR = Path("test-configs")
DEFAULT_CONFIG = TEST_CONFIGS_DIR / "default-config.xml"

# Project root for running commands
PROJECT_ROOT = Path(__file__).parent.parent.parent


class TestPathSecurityCLI:
    """Integration tests for path security via CLI"""

    def test_relative_path_works(self):
        """Relative paths should work normally"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "output.xml"
            result = subprocess.run(
                [sys.executable, "-m", "pfsense_redactor",
                 str(DEFAULT_CONFIG), str(output)],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                check=False
            )
            assert result.returncode == 0
            assert output.exists()

    def test_absolute_path_blocked_by_default(self):
        """Absolute paths outside safe locations should be blocked by default"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "output.xml"
            # Use absolute path to a non-safe location (e.g., /opt)
            # Note: paths under CWD, home, and temp are considered "safe" and allowed
            unsafe_input = "/opt/config.xml"
            result = subprocess.run(
                [sys.executable, "-m", "pfsense_redactor",
                 unsafe_input, str(output)],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                check=False
            )
            assert result.returncode != 0
            assert "Absolute paths not allowed" in result.stderr or "not found" in result.stderr.lower()

    def test_absolute_path_allowed_with_flag(self):
        """Absolute paths should work with --allow-absolute-paths"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "output.xml"
            abs_config = (PROJECT_ROOT / DEFAULT_CONFIG).resolve()
            result = subprocess.run(
                [sys.executable, "-m", "pfsense_redactor",
                 str(abs_config), str(output.resolve()),
                 "--allow-absolute-paths"],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                check=False
            )
            assert result.returncode == 0
            assert output.exists()

    def test_directory_traversal_blocked(self):
        """Directory traversal should be blocked"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "output.xml"
            # Try to use directory traversal in input path
            result = subprocess.run(
                [sys.executable, "-m", "pfsense_redactor",
                 "../../../etc/passwd", str(output)],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                check=False
            )
            assert result.returncode != 0
            assert "traversal" in result.stderr.lower()

    def test_directory_traversal_in_output_blocked(self):
        """Directory traversal in output path should be blocked"""
        result = subprocess.run(
            [sys.executable, "-m", "pfsense_redactor",
             str(DEFAULT_CONFIG), "../../../tmp/output.xml"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            check=False
        )
        assert result.returncode != 0
        assert "traversal" in result.stderr.lower()

    def test_etc_passwd_blocked(self):
        """Attempting to read /etc/passwd should be blocked"""
        # Skip on Windows where /etc/passwd doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "output.xml"
            result = subprocess.run(
                [sys.executable, "-m", "pfsense_redactor",
                 "/etc/passwd", str(output), "--allow-absolute-paths"],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                check=False
            )
            # Should fail either due to not being XML or file not found
            assert result.returncode != 0

    def test_writing_to_etc_blocked(self):
        """Writing to /etc should be blocked"""
        # Skip on Windows where /etc doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        result = subprocess.run(
            [sys.executable, "-m", "pfsense_redactor",
             str(DEFAULT_CONFIG), "/etc/test-output.xml",
             "--allow-absolute-paths"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            check=False
        )
        assert result.returncode != 0
        assert "sensitive" in result.stderr.lower() or "system" in result.stderr.lower()

    def test_writing_to_tmp_allowed(self):
        """Writing to /tmp should be allowed (it's a temp directory)"""
        # Skip on Windows where /tmp doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        # Use a unique filename to avoid conflicts
        output_file = f"/tmp/test-output-{os.getpid()}.xml"
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pfsense_redactor",
                 str(DEFAULT_CONFIG), output_file],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                check=False
            )
            assert result.returncode == 0
            assert Path(output_file).exists()
        finally:
            # Clean up
            if Path(output_file).exists():
                Path(output_file).unlink()

    def test_inplace_with_system_file_blocked(self):
        """In-place editing of system files should be blocked"""
        # Skip on Windows where /etc/hosts doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        result = subprocess.run(
            [sys.executable, "-m", "pfsense_redactor",
             "/etc/hosts", "--inplace", "--force",
             "--allow-absolute-paths"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            check=False
        )
        assert result.returncode != 0
        assert "Cannot use --inplace" in result.stderr or "sensitive" in result.stderr.lower()

    def test_stdout_mode_with_relative_path(self):
        """Stdout mode should work with relative paths"""
        result = subprocess.run(
            [sys.executable, "-m", "pfsense_redactor",
             str(DEFAULT_CONFIG), "--stdout"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            check=False
        )
        assert result.returncode == 0
        assert "<?xml" in result.stdout

    def test_dry_run_with_dangerous_path(self):
        """Dry run should still validate paths"""
        # Skip on Windows where /etc doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        result = subprocess.run(
            [sys.executable, "-m", "pfsense_redactor",
             str(DEFAULT_CONFIG), "/etc/test.xml",
             "--dry-run", "--allow-absolute-paths"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent.parent),
            check=False
        )
        assert result.returncode != 0
        assert "sensitive" in result.stderr.lower() or "system" in result.stderr.lower()

    def test_safe_absolute_path_in_home(self):
        """Absolute paths in home directory should work with flag"""
        # Create a temp file in home directory
        home_output = Path.home() / f"test-output-{os.getpid()}.xml"
        abs_config = (PROJECT_ROOT / DEFAULT_CONFIG).resolve()
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pfsense_redactor",
                 str(abs_config), str(home_output),
                 "--allow-absolute-paths"],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                check=False
            )
            assert result.returncode == 0
            assert home_output.exists()
        finally:
            # Clean up
            if home_output.exists():
                home_output.unlink()

    def test_null_byte_in_path_blocked(self):
        """Paths with null bytes should be blocked"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Python will likely reject this before it reaches our code,
            # but test anyway
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pfsense_redactor",
                     str(DEFAULT_CONFIG), f"{tmpdir}/output\x00.xml"],
                    capture_output=True,
                    text=True,
                    cwd=str(PROJECT_ROOT),
                    check=False
                )
                # Should fail one way or another
                assert result.returncode != 0
            except (ValueError, OSError):
                # Expected - null bytes in paths are rejected by OS
                pass

    def test_windows_system32_blocked(self):
        """Writing to Windows System32 should be blocked"""
        if sys.platform != 'win32':
            pytest.skip("Windows-specific test")

        result = subprocess.run(
            [sys.executable, "-m", "pfsense_redactor",
             str(DEFAULT_CONFIG), "C:\\Windows\\System32\\test.xml",
             "--allow-absolute-paths"],
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            check=False
        )
        assert result.returncode != 0
        assert "sensitive" in result.stderr.lower() or "system" in result.stderr.lower()

    def test_relative_path_with_subdirs(self):
        """Relative paths with subdirectories should work"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "subdir1" / "subdir2"
            output_dir.mkdir(parents=True)
            output = output_dir / "output.xml"

            result = subprocess.run(
                [sys.executable, "-m", "pfsense_redactor",
                 str(DEFAULT_CONFIG), str(output)],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                check=False
            )
            assert result.returncode == 0
            assert output.exists()


class TestPathSecurityEdgeCases:
    """Test edge cases for path security"""

    def test_symlink_to_etc_blocked(self):
        """Symbolic links to /etc should be blocked"""
        # Skip on Windows where /etc doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        if not hasattr(os, 'symlink'):
            pytest.skip("Symlinks not supported on this platform")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create symlink to /etc (if we have permission)
            symlink_path = Path(tmpdir) / "etc_link"
            try:
                symlink_path.symlink_to("/etc")
            except (OSError, NotImplementedError):
                pytest.skip("Cannot create symlinks (permission denied or not supported)")

            output = symlink_path / "test.xml"
            result = subprocess.run(
                [sys.executable, "-m", "pfsense_redactor",
                 str(DEFAULT_CONFIG), str(output),
                 "--allow-absolute-paths"],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                check=False
            )
            assert result.returncode != 0

    def test_current_directory_safe(self):
        """Current directory should be safe for output"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "output.xml"
            result = subprocess.run(
                [sys.executable, "-m", "pfsense_redactor",
                 str(DEFAULT_CONFIG), str(output)],
                capture_output=True,
                text=True,
                cwd=str(PROJECT_ROOT),
                check=False
            )
            assert result.returncode == 0
            assert output.exists()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
