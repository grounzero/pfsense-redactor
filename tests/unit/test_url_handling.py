#!/usr/bin/env python3
"""
URL handling tests

Tests for URL masking, reconstruction, and IPv6 URL handling
"""

import pytest


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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
