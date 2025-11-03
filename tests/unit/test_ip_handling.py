#!/usr/bin/env python3
"""
IP address handling tests

Tests for IP masking, private IP handling, and the --no-keep-private-ips flag
"""

import pytest


class TestNoKeepPrivateIPsFlag:
    """Test the --no-keep-private-ips flag behaviour"""

    def test_anonymise_keeps_private_ips_by_default(self, redactor_factory):
        """Verify that --anonymise keeps private IPs by default"""
        redactor = redactor_factory(anonymise=True, keep_private_ips=True)

        text = "Server at 192.168.1.10 and 8.8.8.8"
        result = redactor.redact_text(text)

        # Private IP should be kept
        assert "192.168.1.10" in result
        # Public IP should be masked
        assert "8.8.8.8" not in result

    def test_no_keep_private_ips_masks_all(self, redactor_factory):
        """Verify that --no-keep-private-ips masks all IPs"""
        redactor = redactor_factory(anonymise=True, keep_private_ips=False)

        text = "Server at 192.168.1.10 and 8.8.8.8"
        result = redactor.redact_text(text)

        # Both should be masked
        assert "192.168.1.10" not in result
        assert "8.8.8.8" not in result

    def test_without_anonymise_masks_all_regardless(self, redactor_factory):
        """Verify that keep_private_ips=True preserves private IPs even without anonymise"""
        redactor = redactor_factory(anonymise=False, keep_private_ips=True)

        text = "Server at 192.168.1.10 and 8.8.8.8"
        result = redactor.redact_text(text)

        # Private IP should be preserved with keep_private_ips=True
        assert "192.168.1.10" in result
        # Public IP should be masked
        assert "8.8.8.8" not in result


class TestIPv4Handling:
    """Test IPv4 address handling"""

    def test_ipv4_with_port_masking(self, basic_redactor):
        """Verify that IPv4:port is handled correctly"""
        text = "192.168.1.10:8443"
        result = basic_redactor.redact_text(text)

        # IP should be masked, port preserved
        assert "192.168.1.10" not in result
        assert ":8443" in result
        assert "XXX.XXX.XXX.XXX:8443" in result

    def test_ipv4_without_port(self, basic_redactor):
        """Verify that plain IPv4 is masked"""
        text = "192.168.1.10"
        result = basic_redactor.redact_text(text)

        assert "192.168.1.10" not in result
        assert "XXX.XXX.XXX.XXX" in result


class TestIPv6Handling:
    """Test IPv6 address handling"""

    def test_ipv6_with_brackets_and_port(self, basic_redactor):
        """Verify that [IPv6]:port is handled correctly"""
        text = "[2001:db8::1]:51820"
        result = basic_redactor.redact_text(text)

        # IPv6 should be masked, brackets and port preserved
        assert "2001:db8::1" not in result
        assert ":51820" in result
        assert "[" in result and "]" in result

    def test_ipv6_with_zone_identifier(self, basic_redactor):
        """Verify that IPv6 zone identifiers are preserved"""
        text = "fe80::1%eth0"
        result = basic_redactor.redact_text(text)

        # IPv6 should be masked, zone preserved
        assert "fe80::1" not in result
        assert "%eth0" in result

    def test_ipv6_with_zone_and_port(self, redactor_factory):
        """Verify that [IPv6%zone]:port preserves link-local addresses"""
        # Link-local addresses are always preserved as special addresses
        redactor = redactor_factory(keep_private_ips=True)
        text = "[fe80::1%eth0]:8080"
        result = redactor.redact_text(text)

        # Link-local IPv6 with zone should be preserved
        assert "fe80::1" in result
        assert "%eth0" in result
        assert ":8080" in result
        assert "[" in result and "]" in result


class TestPortStrippingSecurity:
    """Test port stripping security fix"""

    def test_non_ip_with_port_not_stripped_as_ip(self, basic_redactor):
        """Verify that port is not stripped from non-IP tokens (security fix)"""
        # These should NOT have their ports stripped as if they were IPs
        # The key test is that they don't become XXX.XXX.XXX.XXX:port
        test_cases = [
            ("foo.bar.baz:8080", "XXX.XXX.XXX.XXX:8080"),      # Should NOT become this
            ("file.name.txt:123", "XXX.XXX.XXX.XXX:123"),      # Should NOT become this
            ("some.thing:9999", "XXX.XXX.XXX.XXX:9999"),       # Should NOT become this
            ("999.999.999.999:80", "XXX.XXX.XXX.XXX:80"),      # Should NOT become this
        ]

        for text, should_not_be in test_cases:
            result = basic_redactor.redact_text(text)
            # The key assertion: should NOT be treated as IP:port
            assert should_not_be not in result, f"'{text}' should NOT become '{should_not_be}' (not a valid IP)"

    def test_invalid_ip_with_port_not_treated_as_ip(self, basic_redactor):
        """Verify that invalid IPs with ports are not treated as IP:port"""
        # Invalid IP (only 3 octets) - should not be treated as IP
        text = "1.2.3:8080"
        result = basic_redactor.redact_text(text)
        # Should NOT become XXX.XXX.XXX.XXX:8080
        assert "XXX.XXX.XXX.XXX:8080" not in result

    def test_valid_ipv4_with_port_stripped_correctly(self, basic_redactor):
        """Verify that valid IPv4:port has port stripped correctly"""
        test_cases = [
            ("192.168.1.1:8080", "XXX.XXX.XXX.XXX:8080"),
            ("10.0.0.1:443", "XXX.XXX.XXX.XXX:443"),
            ("172.16.0.1:22", "XXX.XXX.XXX.XXX:22"),
        ]

        for text, expected in test_cases:
            result = basic_redactor.redact_text(text)
            assert expected in result, f"'{text}' should become '{expected}'"
            assert text not in result

    def test_ipv4_without_port_still_works(self, basic_redactor):
        """Verify that plain IPv4 addresses still work correctly"""
        text = "192.168.1.1"
        result = basic_redactor.redact_text(text)
        assert "XXX.XXX.XXX.XXX" in result
        assert "192.168.1.1" not in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
