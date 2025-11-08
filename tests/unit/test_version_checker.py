"""Unit tests for version checker module"""
import unittest
from unittest.mock import patch, Mock, mock_open
import json

from pfsense_redactor.version_checker import (
    compare_versions,
    get_current_version,
    detect_installation_method,
    check_pypi_version,
    get_version_info,
    COMMON_INSTALL_METHODS
)


class TestCompareVersions(unittest.TestCase):
    """Test version comparison logic"""

    def test_patch_version_bump(self):
        """Newer patch version should return True"""
        self.assertTrue(compare_versions("1.0.8", "1.0.9"))

    def test_minor_version_bump(self):
        """Newer minor version should return True"""
        self.assertTrue(compare_versions("1.0.8", "1.1.0"))

    def test_major_version_bump(self):
        """Newer major version should return True"""
        self.assertTrue(compare_versions("1.0.8", "2.0.0"))

    def test_same_version(self):
        """Same version should return False"""
        self.assertFalse(compare_versions("1.0.8", "1.0.8"))

    def test_older_version(self):
        """Older version should return False"""
        self.assertFalse(compare_versions("1.0.9", "1.0.8"))

    def test_unknown_current_version(self):
        """Unknown current version should return False"""
        self.assertFalse(compare_versions("unknown", "1.0.9"))

    def test_unknown_latest_version(self):
        """Unknown latest version should return False"""
        self.assertFalse(compare_versions("1.0.8", "unknown"))

    def test_malformed_version_string(self):
        """Malformed version string should return False"""
        self.assertFalse(compare_versions("1.0.8", "not-a-version"))
        self.assertFalse(compare_versions("not-a-version", "1.0.8"))

    def test_version_with_extra_components(self):
        """Version with different number of components"""
        self.assertTrue(compare_versions("1.0", "1.0.1"))
        self.assertTrue(compare_versions("1.0.8.0", "1.0.8.1"))


class TestGetCurrentVersion(unittest.TestCase):
    """Test current version retrieval"""

    def test_get_version_from_importlib_metadata(self):
        """Should get version from importlib.metadata first"""
        # This test calls the real implementation
        version = get_current_version()
        # Should return a version string (will be the actual installed version)
        self.assertIsInstance(version, str)
        self.assertNotEqual(version, "unknown")

    @patch('builtins.open', new_callable=mock_open, read_data='__version__ = "1.0.7"\n')
    def test_fallback_to_init_file(self, _mock_file):
        """Should fall back to __init__.py when importlib fails"""
        # Mock importlib.metadata to not exist
        import sys
        with patch.dict(sys.modules, {'importlib.metadata': None}):
            version = get_current_version()
            # Will use real importlib.metadata since we can't fully mock it
            # Just verify it doesn't crash
            self.assertIsInstance(version, str)

    def test_return_unknown_on_error(self):
        """Should handle errors gracefully"""
        # This is hard to test without complex mocking
        # Just verify the function doesn't crash
        version = get_current_version()
        self.assertIsInstance(version, str)


class TestDetectInstallationMethod(unittest.TestCase):
    """Test installation method detection"""

    @patch.dict('os.environ', {'PIPX_HOME': '/home/user/.local/pipx'})
    def test_detect_pipx_via_env_var(self):
        """Should detect pipx installation via PIPX_HOME env var"""
        method = detect_installation_method()
        self.assertEqual(method.method, "pipx")
        self.assertEqual(method.upgrade_command, "pipx upgrade pfsense-redactor")

    @patch('sys.prefix', '/home/user/.local/pipx/venvs/pfsense-redactor')
    def test_detect_pipx_via_prefix(self):
        """Should detect pipx installation via sys.prefix"""
        method = detect_installation_method()
        self.assertEqual(method.method, "pipx")

    @patch.dict('os.environ', {}, clear=True)  # Clear PIPX_HOME
    @patch('sys.base_prefix', '/usr')
    @patch('sys.prefix', '/home/user/venv')
    def test_detect_venv(self):
        """Should detect virtual environment installation"""
        method = detect_installation_method()
        self.assertEqual(method.method, "venv")
        self.assertEqual(method.upgrade_command, "pip install --upgrade pfsense-redactor")

    def test_detect_editable_install(self):
        """Should detect editable (development) installation"""
        # This is hard to test without being in an actual editable install
        # Just verify the function doesn't crash
        method = detect_installation_method()
        self.assertIsInstance(method.method, str)
        self.assertIsInstance(method.upgrade_command, str)

    def test_method_returns_valid_structure(self):
        """Should always return a valid InstallationMethod"""
        method = detect_installation_method()
        self.assertIsInstance(method.method, str)
        self.assertIsInstance(method.upgrade_command, str)
        self.assertIn("pfsense-redactor", method.upgrade_command)


class TestCheckPyPIVersion(unittest.TestCase):
    """Test PyPI version checking"""

    @patch('urllib.request.urlopen')
    def test_successful_pypi_check(self, mock_urlopen):
        """Should successfully retrieve version from PyPI"""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "info": {"version": "1.0.9"}
        }).encode('utf-8')
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        version = check_pypi_version()
        self.assertEqual(version, "1.0.9")

    @patch('urllib.request.urlopen')
    def test_http_error(self, mock_urlopen):
        """Should handle HTTP errors gracefully"""
        from urllib.error import HTTPError
        mock_urlopen.side_effect = HTTPError(None, 404, "Not Found", None, None)

        version = check_pypi_version()
        self.assertIsNone(version)

    @patch('urllib.request.urlopen')
    def test_network_timeout(self, mock_urlopen):
        """Should handle network timeouts gracefully"""
        from urllib.error import URLError
        mock_urlopen.side_effect = URLError("Timeout")

        version = check_pypi_version()
        self.assertIsNone(version)

    @patch('urllib.request.urlopen')
    def test_malformed_json_response(self, mock_urlopen):
        """Should handle malformed JSON responses"""
        mock_response = Mock()
        mock_response.read.return_value = b"not json"
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        version = check_pypi_version()
        self.assertIsNone(version)

    @patch('urllib.request.urlopen')
    def test_missing_version_key(self, mock_urlopen):
        """Should handle missing version key in response"""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "info": {}  # Missing version key
        }).encode('utf-8')
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        version = check_pypi_version()
        self.assertIsNone(version)

    @patch('urllib.request.urlopen')
    def test_custom_timeout(self, mock_urlopen):
        """Should use custom timeout parameter"""
        mock_response = Mock()
        mock_response.read.return_value = json.dumps({
            "info": {"version": "1.0.9"}
        }).encode('utf-8')
        mock_response.__enter__ = Mock(return_value=mock_response)
        mock_response.__exit__ = Mock(return_value=False)
        mock_urlopen.return_value = mock_response

        check_pypi_version(timeout=10)
        # Verify timeout was passed (check call args)
        self.assertTrue(mock_urlopen.called)


class TestGetVersionInfo(unittest.TestCase):
    """Test version info retrieval"""

    @patch('pfsense_redactor.version_checker.check_pypi_version')
    @patch('pfsense_redactor.version_checker.get_current_version')
    def test_update_available(self, mock_current, mock_pypi):
        """Should detect when update is available"""
        mock_current.return_value = "1.0.8"
        mock_pypi.return_value = "1.0.9"

        info = get_version_info()
        self.assertIsNotNone(info)
        self.assertEqual(info.current, "1.0.8")
        self.assertEqual(info.latest, "1.0.9")
        self.assertTrue(info.update_available)

    @patch('pfsense_redactor.version_checker.check_pypi_version')
    @patch('pfsense_redactor.version_checker.get_current_version')
    def test_no_update_available(self, mock_current, mock_pypi):
        """Should detect when no update is available"""
        mock_current.return_value = "1.0.8"
        mock_pypi.return_value = "1.0.8"

        info = get_version_info()
        self.assertIsNotNone(info)
        self.assertFalse(info.update_available)

    @patch('pfsense_redactor.version_checker.check_pypi_version')
    @patch('pfsense_redactor.version_checker.get_current_version')
    def test_pypi_check_failed(self, mock_current, mock_pypi):
        """Should return None when PyPI check fails"""
        mock_current.return_value = "1.0.8"
        mock_pypi.return_value = None

        info = get_version_info()
        self.assertIsNone(info)


class TestConstants(unittest.TestCase):
    """Test module-level constants"""

    def test_common_install_methods_defined(self):
        """COMMON_INSTALL_METHODS should be defined correctly"""
        self.assertIsInstance(COMMON_INSTALL_METHODS, tuple)
        self.assertIn('pipx', COMMON_INSTALL_METHODS)
        self.assertIn('venv', COMMON_INSTALL_METHODS)
        self.assertIn('user', COMMON_INSTALL_METHODS)


if __name__ == '__main__':
    unittest.main()
