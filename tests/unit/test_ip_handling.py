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


if __name__ == '__main__':
    pytest.main([__file__, '-v'])