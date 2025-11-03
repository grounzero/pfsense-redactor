#!/usr/bin/env python3
"""
URL handling tests

Tests for URL masking, reconstruction, and IPv6 URL handling
"""

import pytest
from urllib.parse import urlparse


class TestNormaliseMaskedURLAnonymise:
    """Test that _normalise_masked_url works correctly in anonymise mode"""

    def test_masked_url_uses_alias_in_anonymise_mode(self, redactor_factory):
        """Verify that already-masked URLs get aliases in anonymise mode"""
        redactor = redactor_factory(anonymise=True)

        # Simulate a URL that's already been masked
        url = "http://XXX.XXX.XXX.XXX/path"
        result = redactor._mask_url(url)

        # Should use an alias, not example.com
        assert "XXX.XXX.XXX.XXX" not in result
        # Should have domain alias format
        assert "domain" in result and ".example" in result

    def test_masked_url_uses_example_com_without_anonymise(self, basic_redactor):
        """Verify that masked URLs use example.com without anonymise"""
        url = "http://XXX.XXX.XXX.XXX/path"
        result = basic_redactor._mask_url(url)

        # Should use example.com
        assert "example.com" in result
        assert "domain1" not in result

    def test_multiple_masked_urls_get_same_alias(self, redactor_factory):
        """Verify that multiple masked URLs get the same alias"""
        redactor = redactor_factory(anonymise=True)

        url1 = "http://XXX.XXX.XXX.XXX/path1"
        url2 = "http://XXX.XXX.XXX.XXX/path2"

        result1 = redactor._mask_url(url1)
        result2 = redactor._mask_url(url2)

        # Extract the host from both results
        # Both should use the same alias
        assert result1.split('/')[2] == result2.split('/')[2]


class TestURLWithIPHandling:
    """Test URL handling with IP addresses"""

    def test_url_with_ipv4_and_port(self, basic_redactor):
        """Verify that URLs with IPv4:port are handled correctly"""
        url = "https://192.168.1.10:8443/admin"
        result = basic_redactor._mask_url(url)

        # Should mask IP but preserve port and path
        assert "192.168.1.10" not in result
        assert ":8443" in result
        assert "/admin" in result

    def test_url_with_bracketed_ipv6_and_port(self, basic_redactor):
        """Verify that URLs with [IPv6]:port are handled correctly"""
        url = "https://[2001:db8::1]:51820/ui"
        result = basic_redactor._mask_url(url)

        # Should mask IP but preserve brackets, port, and path
        assert "2001:db8::1" not in result
        assert ":51820" in result
        assert "/ui" in result
        # Should have brackets around masked IPv6
        assert "[" in result and "]" in result


class TestNonHTTPProtocolURLs:
    """Test URL handling for protocols other than HTTP/HTTPS"""

    def test_ftp_url_with_credentials_redacted(self, basic_redactor):
        """Verify that FTP URLs with credentials are properly redacted"""
        url = "ftp://user:password@ftp.example.com/files"
        result = basic_redactor._mask_url(url)

        # Should redact password
        assert "password" not in result
        assert "REDACTED" in result
        # Should preserve username and protocol
        assert "ftp://" in result
        assert "user" in result
        # Should mask domain
        assert "ftp.example.com" not in result

    def test_ftps_url_with_credentials_redacted(self, basic_redactor):
        """Verify that FTPS URLs with credentials are properly redacted"""
        url = "ftps://admin:secret123@secure.example.org:990/data"
        result = basic_redactor._mask_url(url)

        # Should redact password
        assert "secret123" not in result
        assert "REDACTED" in result
        # Should preserve protocol and username
        assert "ftps://" in result
        assert "admin" in result
        # Should preserve port
        assert ":990" in result

    def test_sftp_url_with_credentials_redacted(self, basic_redactor):
        """Verify that SFTP URLs with credentials are properly redacted"""
        url = "sftp://backup:pass@192.168.1.100/backups"
        result = basic_redactor._mask_url(url)

        # Should redact password
        assert "pass" not in result
        assert "REDACTED" in result
        # Should mask IP
        assert "192.168.1.100" not in result

    def test_ssh_url_with_credentials_redacted(self, basic_redactor):
        """Verify that SSH URLs with credentials are properly redacted"""
        url = "ssh://root:toor@server.local:22"
        result = basic_redactor._mask_url(url)

        # Should redact password
        assert "toor" not in result
        assert "REDACTED" in result
        assert "ssh://" in result

    def test_telnet_url_with_credentials_redacted(self, basic_redactor):
        """Verify that Telnet URLs with credentials are properly redacted"""
        url = "telnet://admin:admin@router.local:23"
        result = basic_redactor._mask_url(url)

        # Should redact password
        assert "REDACTED" in result
        assert "telnet://" in result

    def test_file_url_local_path_preserved(self, basic_redactor):
        """Verify that file:// URLs with local paths are preserved unchanged"""
        url = "file:///etc/config.xml"
        result = basic_redactor._mask_url(url)

        # file:// URLs without hostnames should be preserved exactly
        assert result == url

    def test_file_url_windows_path_preserved(self, basic_redactor):
        """Verify that file:// URLs with Windows paths are preserved"""
        url = "file:///C:/Users/admin/config.xml"
        result = basic_redactor._mask_url(url)

        # Should be preserved exactly, not transformed to network path
        assert result == url

    def test_file_url_with_hostname_redacted(self, basic_redactor):
        """Verify that file:// URLs with actual hostnames are redacted"""
        url = "file://fileserver.local/share/config.xml"
        result = basic_redactor._mask_url(url)

        # Should mask the hostname
        assert "fileserver.local" not in result
        assert urlparse(result).hostname == "example.com"
        assert "file://" in result

    def test_nfs_url_without_hostname_preserved(self, basic_redactor):
        """Verify that NFS URLs without hostnames are preserved"""
        url = "nfs:///mnt/share"
        result = basic_redactor._mask_url(url)

        # Should be preserved unchanged
        assert result == url

    def test_smb_url_without_hostname_preserved(self, basic_redactor):
        """Verify that SMB URLs without hostnames are preserved"""
        url = "smb:///share"
        result = basic_redactor._mask_url(url)

        # Should be preserved unchanged
        assert result == url

    def test_smb_url_with_credentials_redacted(self, basic_redactor):
        """Verify that SMB URLs with credentials are properly redacted"""
        url = "smb://domain\\user:password@fileserver/share"
        result = basic_redactor._mask_url(url)

        # Should redact password
        assert "password" not in result
        assert "REDACTED" in result
        assert "smb://" in result

    def test_mixed_protocols_in_text(self, basic_redactor):
        """Verify that multiple protocol URLs in text are all redacted"""
        text = """
        FTP: ftp://user:pass@ftp.example.com/files
        HTTPS: https://admin:secret@web.example.com/admin
        SFTP: sftp://backup:key@192.168.1.50/data
        """
        result = basic_redactor.redact_text(text)

        # All passwords should be redacted
        assert "pass" not in result
        assert "secret" not in result
        assert "key" not in result
        # Should have REDACTED markers
        assert result.count("REDACTED") >= 3
        # Protocols should be preserved
        assert "ftp://" in result
        assert "https://" in result
        assert "sftp://" in result


class TestURLUsernameRedaction:
    """Test URL username redaction feature"""

    def test_username_preserved_by_default(self, basic_redactor):
        """Verify that usernames are preserved by default"""
        url = "ftp://admin:password@ftp.example.com/files"
        result = basic_redactor._mask_url(url)

        # Username should be preserved
        assert "admin" in result
        # Password should be redacted
        assert "password" not in result
        assert "REDACTED" in result

    def test_username_redacted_with_flag(self, redactor_factory):
        """Verify that usernames are redacted when flag is set"""
        redactor = redactor_factory(redact_url_usernames=True)
        url = "ftp://admin:password@ftp.example.com/files"
        result = redactor._mask_url(url)

        # Username should be redacted
        assert "admin" not in result
        # Should have REDACTED for both username and password
        assert "REDACTED" in result
        # Should have the pattern REDACTED:REDACTED@
        assert "REDACTED:REDACTED@" in result

    def test_username_only_url_preserved_by_default(self, basic_redactor):
        """Verify that username-only URLs preserve username by default"""
        url = "ftp://anonymous@ftp.example.com/pub"
        result = basic_redactor._mask_url(url)

        # Username should be preserved (no password)
        assert "anonymous" in result
        assert "REDACTED" not in result

    def test_username_only_url_redacted_with_flag(self, redactor_factory):
        """Verify that username-only URLs redact username with flag"""
        redactor = redactor_factory(redact_url_usernames=True)
        url = "ftp://anonymous@ftp.example.com/pub"
        result = redactor._mask_url(url)

        # Username should be redacted
        assert "anonymous" not in result
        assert "REDACTED@" in result
        # Should not have :REDACTED since there's no password
        assert ":REDACTED" not in result

    def test_multiple_urls_with_different_usernames(self, redactor_factory):
        """Verify that multiple URLs with different usernames are handled correctly"""
        redactor = redactor_factory(redact_url_usernames=True)

        text = """
        ftp://admin:pass1@server1.com/data
        ftp://backup:pass2@server2.com/files
        ftp://guest@server3.com/public
        """
        result = redactor.redact_text(text)

        # All usernames should be redacted
        assert "admin" not in result
        assert "backup" not in result
        assert "guest" not in result
        # All passwords should be redacted
        assert "pass1" not in result
        assert "pass2" not in result

    def test_sensitive_usernames_redacted(self, redactor_factory):
        """Verify that sensitive usernames like 'root' and 'admin' can be redacted"""
        redactor = redactor_factory(redact_url_usernames=True)

        test_cases = [
            "ssh://root:toor@server.local",
            "ftp://admin:admin@router.local",
            "telnet://administrator:pass@switch.local",
        ]

        for url in test_cases:
            result = redactor._mask_url(url)
            # Usernames should be redacted
            assert "root" not in result
            assert "admin" not in result
            assert "administrator" not in result
            assert "REDACTED" in result

    def test_http_basic_auth_username_handling(self, redactor_factory):
        """Verify that HTTP basic auth usernames are handled correctly"""
        # Without flag - preserve username
        redactor_preserve = redactor_factory(redact_url_usernames=False)
        url = "https://apiuser:apikey@api.example.com/v1/data"
        result = redactor_preserve._mask_url(url)
        assert "apiuser" in result
        assert "apikey" not in result

        # With flag - redact username
        redactor_redact = redactor_factory(redact_url_usernames=True)
        result = redactor_redact._mask_url(url)
        assert "apiuser" not in result
        assert "apikey" not in result
        assert "REDACTED:REDACTED@" in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
