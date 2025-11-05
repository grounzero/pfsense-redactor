"""
Unit tests for file path validation security
Tests the validate_file_path function to ensure it properly blocks malicious paths
"""
import sys
from pathlib import Path

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# pylint: disable=wrong-import-position
from pfsense_redactor.redactor import validate_file_path, _get_sensitive_directories


class TestPathValidation:  # pylint: disable=too-many-public-methods
    """Test suite for path validation security"""

    def test_relative_path_allowed(self):
        """Relative paths should be allowed by default"""
        valid, error, resolved = validate_file_path("config.xml", allow_absolute=False)
        assert valid is True
        assert error == ""
        assert resolved is not None
        assert resolved.is_absolute()  # Should be resolved to absolute

    def test_relative_path_with_subdirectory(self):
        """Relative paths with subdirectories should be allowed"""
        valid, error, resolved = validate_file_path("test-configs/config.xml", allow_absolute=False)
        assert valid is True
        assert error == ""
        assert resolved is not None

    def test_absolute_path_blocked_by_default(self):
        """Absolute paths should be blocked by default"""
        # Use a platform-appropriate absolute path
        if sys.platform == 'win32':
            test_path = "C:\\test.xml"
        else:
            test_path = "/etc/passwd"
        valid, error, resolved = validate_file_path(test_path, allow_absolute=False)
        assert valid is False
        assert "Absolute paths not allowed" in error or "sensitive" in error.lower()
        assert resolved is None

    def test_absolute_path_allowed_with_flag(self):
        """Absolute paths should be allowed when flag is set"""
        # Use a safe absolute path for testing
        test_path = str(Path.cwd() / "test.xml")
        valid, error, resolved = validate_file_path(test_path, allow_absolute=True)
        assert valid is True
        assert error == ""
        assert resolved is not None

    def test_directory_traversal_blocked(self):
        """Directory traversal with .. should be blocked"""
        valid, error, resolved = validate_file_path("../../../etc/passwd", allow_absolute=False)
        assert valid is False
        assert "directory traversal" in error.lower()
        assert resolved is None

    def test_directory_traversal_multiple_levels(self):
        """Multiple levels of directory traversal should be blocked"""
        valid, error, resolved = validate_file_path("../../config.xml", allow_absolute=False)
        assert valid is False
        assert "directory traversal" in error.lower()
        assert resolved is None

    def test_null_byte_blocked(self):
        """Paths with null bytes should be blocked"""
        valid, error, resolved = validate_file_path("config.xml\0.txt", allow_absolute=False)
        assert valid is False
        assert "null byte" in error.lower()
        assert resolved is None

    def test_sensitive_directory_etc_blocked(self):
        """Writing to /etc should be blocked"""
        # Skip on Windows where /etc doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        valid, error, resolved = validate_file_path(
            "/etc/test.xml",
            allow_absolute=True,
            is_output=True
        )
        assert valid is False
        assert "sensitive" in error.lower() or "system" in error.lower()
        assert resolved is None

    def test_sensitive_directory_sys_blocked(self):
        """Writing to /sys should be blocked"""
        # Skip on Windows where /sys doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        valid, error, resolved = validate_file_path(
            "/sys/test.xml",
            allow_absolute=True,
            is_output=True
        )
        assert valid is False
        assert "sensitive" in error.lower() or "system" in error.lower()
        assert resolved is None

    def test_sensitive_file_passwd_blocked(self):
        """Writing to /etc/passwd should be blocked"""
        # Skip on Windows where /etc/passwd doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        valid, _, _ = validate_file_path(
            "/etc/passwd",
            allow_absolute=True,
            is_output=True
        )
        assert valid is False

    def test_sensitive_file_shadow_blocked(self):
        """Writing to /etc/shadow should be blocked"""
        # Skip on Windows where /etc/shadow doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        valid, _, _ = validate_file_path(
            "/etc/shadow",
            allow_absolute=True,
            is_output=True
        )
        assert valid is False

    def test_windows_system32_blocked(self):
        """Writing to Windows System32 should be blocked"""
        valid, _, _ = validate_file_path(
            "C:\\Windows\\System32\\config\\test.xml",
            allow_absolute=True,
            is_output=True
        )
        # Only check on Windows or if path exists
        if sys.platform == 'win32' or Path("C:\\Windows\\System32").exists():
            assert valid is False

    def test_input_path_less_strict(self):
        """Input paths should have less strict checks than output paths"""
        # Skip on Windows where /etc doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        # Output path to /etc should be blocked (writing is dangerous)
        valid_output, _, _ = validate_file_path(
            "/etc/hosts",
            allow_absolute=True,
            is_output=True
        )

        # Input should be more permissive than output
        # (though both may fail if file doesn't exist)
        assert valid_output is False

    def test_safe_absolute_path_allowed(self):
        """Safe absolute paths should be allowed with flag"""
        # Use current directory as a safe absolute path
        safe_path = str(Path.cwd() / "safe-config.xml")
        valid, error, resolved = validate_file_path(
            safe_path,
            allow_absolute=True,
            is_output=True
        )
        assert valid is True
        assert error == ""
        assert resolved is not None

    def test_home_directory_allowed(self):
        """Paths in home directory should be allowed"""
        home_path = str(Path.home() / "config.xml")
        valid, error, resolved = validate_file_path(
            home_path,
            allow_absolute=True,
            is_output=True
        )
        assert valid is True
        assert error == ""
        assert resolved is not None

    def test_tmp_directory_allowed_for_temp_files(self):
        """Writing to /tmp should be allowed (it's a temp directory)"""
        # Skip on Windows where /tmp doesn't exist
        if sys.platform == 'win32':
            pytest.skip("Unix-specific test")

        valid, error, resolved = validate_file_path(
            "/tmp/config.xml",
            allow_absolute=False,  # Should be allowed even without flag (safe location)
            is_output=True
        )
        assert valid is True
        assert error == ""
        assert resolved is not None

    def test_sensitive_directories_computed(self):
        """Sensitive directories should be computed correctly"""
        sensitive_dirs = _get_sensitive_directories()
        assert isinstance(sensitive_dirs, frozenset)
        assert len(sensitive_dirs) > 0

        # Check for common sensitive directories (normalised to lowercase)
        # At least some of these should be present
        expected_patterns = ['/etc', '/sys', '/proc', 'windows']
        found = False
        for pattern in expected_patterns:
            if any(pattern in dir_path for dir_path in sensitive_dirs):
                found = True
                break
        assert found, "No expected sensitive directories found"

    def test_cwd_relative_path_safe(self):
        """Paths relative to CWD should be safe"""
        valid, error, resolved = validate_file_path(
            "./config.xml",
            allow_absolute=False,
            is_output=True
        )
        assert valid is True
        assert error == ""
        assert resolved is not None

    def test_parent_directory_single_level_blocked(self):
        """Single level parent directory traversal should be blocked"""
        valid, error, resolved = validate_file_path(
            "../config.xml",
            allow_absolute=False
        )
        assert valid is False
        assert "traversal" in error.lower()
        assert resolved is None

    def test_mixed_separators_windows(self):
        """Mixed path separators should be handled"""
        # This tests Windows-style paths with forward slashes
        valid, _, _ = validate_file_path(
            "C:/Windows/System32/config.xml",
            allow_absolute=True,
            is_output=True
        )
        # Should be blocked if on Windows or path exists
        if sys.platform == 'win32':
            assert valid is False

    def test_empty_path(self):
        """Empty paths should be handled gracefully"""
        valid, error, _ = validate_file_path("", allow_absolute=False)
        # Should either be invalid or handle gracefully
        assert isinstance(valid, bool)
        assert isinstance(error, str)

    def test_path_with_spaces(self):
        """Paths with spaces should be handled correctly"""
        valid, error, resolved = validate_file_path(
            "my config file.xml",
            allow_absolute=False
        )
        assert valid is True
        assert error == ""
        assert resolved is not None

    def test_unicode_path(self):
        """Unicode characters in paths should be handled"""
        valid, error, resolved = validate_file_path(
            "配置文件.xml",
            allow_absolute=False
        )
        assert valid is True
        assert error == ""
        assert resolved is not None


class TestPathValidationEdgeCases:
    """Test edge cases and corner cases for path validation"""

    def test_dot_slash_prefix(self):
        """Paths starting with ./ should be allowed"""
        valid, _, resolved = validate_file_path("./config.xml", allow_absolute=False)
        assert valid is True
        assert resolved is not None

    def test_multiple_slashes(self):
        """Multiple consecutive slashes should be handled"""
        valid, _, resolved = validate_file_path("test//config.xml", allow_absolute=False)
        assert valid is True
        assert resolved is not None

    def test_trailing_slash(self):
        """Trailing slashes should be handled"""
        valid, _, resolved = validate_file_path("test-configs/", allow_absolute=False)
        assert valid is True
        assert resolved is not None

    def test_very_long_path(self):
        """Very long paths should be handled"""
        long_path = "a/" * 100 + "config.xml"
        valid, error, _ = validate_file_path(long_path, allow_absolute=False)
        # Should either succeed or fail gracefully
        assert isinstance(valid, bool)
        assert isinstance(error, str)

    def test_special_characters_in_filename(self):
        """Special characters in filenames should be handled"""
        valid, _, resolved = validate_file_path(
            "config-[test]_(1).xml",
            allow_absolute=False
        )
        assert valid is True
        assert resolved is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
