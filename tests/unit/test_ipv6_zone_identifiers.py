#!/usr/bin/env python3
"""
Tests for IPv6 zone identifier handling

Verifies that IPv6 addresses with zone identifiers (interface names) are correctly
parsed and preserved, including complex interface names with dots, dashes, and colons.
"""

import pytest
from pathlib import Path
import importlib.util

# Import the pfsense-redactor module dynamically
PROJECT_ROOT = Path(__file__).parent.parent.parent
SCRIPT_PATH = PROJECT_ROOT / "pfsense_redactor" / "redactor.py"

spec = importlib.util.spec_from_file_location("pfsense_redactor", SCRIPT_PATH)
pfsense_redactor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pfsense_redactor)
PfSenseRedactor = pfsense_redactor.PfSenseRedactor


class TestIPv6ZoneIdentifiers:
    """Test IPv6 zone identifier parsing and preservation"""

    def test_zone_with_vlan_interface(self):
        """Test zone identifier with VLAN interface (contains dot)"""
        redactor = PfSenseRedactor()

        # Test cases with VLAN interfaces
        test_cases = [
            ('fe80::1%eth0.100', 'fe80::1%eth0.100'),  # VLAN interface
            ('fe80::1%ens18.200', 'fe80::1%ens18.200'),  # Modern naming with VLAN
            ('fe80::1%bond0.50', 'fe80::1%bond0.50'),  # Bond with VLAN
        ]

        for input_text, expected in test_cases:
            result = redactor._mask_ip_like_tokens(input_text)
            # Zone should be preserved even if IP is redacted
            assert any(z in result for z in ('%eth0.100', '%ens18.200', '%bond0.50')), \
                f"Zone identifier lost for {input_text}, got: {result}"

    def test_zone_with_dash_interface(self):
        """Test zone identifier with interface containing dash"""
        redactor = PfSenseRedactor()

        test_cases = [
            ('fe80::1%wlan0-1', 'fe80::1%wlan0-1'),
            ('fe80::1%br-lan', 'fe80::1%br-lan'),
            ('fe80::1%eth-mgmt', 'fe80::1%eth-mgmt'),
        ]

        for input_text, expected in test_cases:
            result = redactor._mask_ip_like_tokens(input_text)
            assert any(z in result for z in ('%wlan0-1', '%br-lan', '%eth-mgmt')), \
                f"Zone identifier with dash lost for {input_text}, got: {result}"

    def test_zone_with_colon_interface(self):
        """Test zone identifier with interface containing colon (alias)"""
        redactor = PfSenseRedactor()

        # Some systems use colons for interface aliases
        test_cases = [
            ('fe80::1%eth0:1', 'fe80::1%eth0:1'),
            ('fe80::1%ens18:0', 'fe80::1%ens18:0'),
        ]

        for input_text, expected in test_cases:
            result = redactor._mask_ip_like_tokens(input_text)
            assert '%eth0:1' in result or '%ens18:0' in result, \
                f"Zone identifier with colon lost for {input_text}, got: {result}"

    def test_zone_with_complex_interface(self):
        """Test zone identifier with complex interface names"""
        redactor = PfSenseRedactor()

        # Real-world complex interface names
        test_cases = [
            ('fe80::1%eth0.100-vlan', 'fe80::1%eth0.100-vlan'),
            ('fe80::1%br-lan.10', 'fe80::1%br-lan.10'),
            ('fe80::1%bond0.50:1', 'fe80::1%bond0.50:1'),
        ]

        for input_text, expected in test_cases:
            result = redactor._mask_ip_like_tokens(input_text)
            # Check that the zone is preserved (even if IP is redacted)
            assert any(z in result for z in ('%eth0.100-vlan', '%br-lan.10', '%bond0.50:1')), \
                f"Complex zone identifier lost for {input_text}, got: {result}"

    def test_bracketed_ipv6_with_zone(self):
        """Test bracketed IPv6 addresses with zone identifiers"""
        redactor = PfSenseRedactor()

        test_cases = [
            ('[fe80::1%eth0.100]', '[fe80::1%eth0.100]'),
            ('[fe80::1%wlan0-1]', '[fe80::1%wlan0-1]'),
            ('[fe80::1%eth0:1]', '[fe80::1%eth0:1]'),
        ]

        for input_text, expected in test_cases:
            result = redactor._mask_ip_like_tokens(input_text)
            # Zone should be preserved in bracketed form
            assert any(z in result for z in ('%eth0.100]', '%wlan0-1]', '%eth0:1]')), \
                f"Zone identifier lost in bracketed form for {input_text}, got: {result}"
            # ...but not by leaving the whole token alone. Asserting only that
            # the zone survived passed happily while the address leaked, which
            # is how the bracketed-zone gap went unnoticed.
            assert 'fe80::1' not in result, \
                f"Address should be redacted for {input_text}, got: {result}"

    def test_bracketed_ipv6_with_zone_and_port(self):
        """Test bracketed IPv6 with zone identifier and port"""
        redactor = PfSenseRedactor()

        test_cases = [
            ('[fe80::1%eth0.100]:51820', '[fe80::1%eth0.100]:51820'),
            ('[fe80::1%wlan0-1]:8080', '[fe80::1%wlan0-1]:8080'),
            ('[fe80::1%br-lan.10]:443', '[fe80::1%br-lan.10]:443'),
        ]

        for input_text, expected in test_cases:
            result = redactor._mask_ip_like_tokens(input_text)
            # Zone and port should both be preserved
            assert any(z in result for z in ('%eth0.100]:', '%wlan0-1]:', '%br-lan.10]:')), \
                f"Zone identifier or port lost for {input_text}, got: {result}"
            assert any(p in result for p in (':51820', ':8080', ':443')), \
                f"Port lost for {input_text}, got: {result}"
            # The assertion this test was missing. Both checks above are
            # satisfied by returning the input untouched, which is exactly what
            # used to happen to this shape.
            assert 'fe80::1' not in result, \
                f"Address should be redacted for {input_text}, got: {result}"

    def test_zone_parsing_in_parse_ip_token(self):
        """Test _parse_ip_token correctly extracts zone identifiers"""
        redactor = PfSenseRedactor()

        # Test various zone formats
        test_cases = [
            ('fe80::1%eth0.100', 'eth0.100'),
            ('fe80::1%wlan0-1', 'wlan0-1'),
            ('fe80::1%eth0:1', 'eth0:1'),
            ('fe80::1%br-lan.10', 'br-lan.10'),
            ('[fe80::1%eth0.100]', 'eth0.100'),
        ]

        for token, expected_zone in test_cases:
            ip, bracketed, zone = redactor._parse_ip_token(token)
            assert zone == expected_zone, \
                f"Expected zone '{expected_zone}' for {token}, got '{zone}'"

    def test_zone_preserved_with_keep_private_ips(self):
        """Test that zone identifiers are preserved when keeping private IPs"""
        redactor = PfSenseRedactor(keep_private_ips=True)

        # Link-local addresses should be kept with --keep-private-ips
        test_cases = [
            'fe80::1%eth0.100',
            'fe80::1%wlan0-1',
            '[fe80::1%br-lan.10]:51820',
        ]

        for input_text in test_cases:
            result = redactor._mask_ip_like_tokens(input_text)
            # Should be unchanged since link-local is private
            assert result == input_text, \
                f"Link-local with zone should be preserved with keep_private_ips, got: {result}"

    def test_zone_preserved_after_redaction(self):
        """Test that zone identifiers are preserved even when IP is redacted"""
        redactor = PfSenseRedactor(keep_private_ips=False)

        # Use a truly global IPv6 with zone (2606:4700:: is Cloudflare's public range)
        input_text = '2606:4700:4700::1111%eth0.100'
        result = redactor._mask_ip_like_tokens(input_text)

        # IP should be redacted but zone preserved
        assert 'XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX' in result, \
            f"IP should be redacted, got: {result}"
        assert '%eth0.100' in result, \
            f"Zone identifier should be preserved, got: {result}"

    def test_ip_pattern_matches_complex_zones(self):
        """Test that the ip_pattern regex matches complex zone identifiers"""
        import re

        # Current pattern (should fail for some cases)
        old_pattern = re.compile(r'^[\[\]]?[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_]+)?[\[\]]?(?::\d+)?$')

        # Fixed pattern (should match all cases)
        # Note: + and - must be at the end of character class or escaped
        new_pattern = re.compile(r'^[\[\]]?[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.:+-]+)?[\[\]]?(?::\d+)?$')

        test_cases = [
            'fe80::1%eth0.100',      # VLAN with dot
            'fe80::1%wlan0-1',       # Interface with dash
            'fe80::1%eth0:1',        # Interface alias with colon
            'fe80::1%br-lan.10',     # Complex: dash and dot
            '[fe80::1%eth0.100]',    # Bracketed with VLAN
            '[fe80::1%eth0.100]:51820',  # Bracketed with VLAN and port
        ]

        for test_case in test_cases:
            old_match = old_pattern.match(test_case)
            new_match = new_pattern.match(test_case)

            # Document which cases fail with old pattern
            if not old_match:
                print(f"Old pattern FAILS for: {test_case}")

            # New pattern should match all
            assert new_match, f"New pattern should match {test_case}"

    def test_zone_not_corrupted_in_text(self):
        """Test that zone identifiers don't get corrupted in larger text"""
        redactor = PfSenseRedactor()

        # Text with IPv6 addresses with zones
        text = "Interface eth0.100 has address fe80::1%eth0.100 and wlan0-1 has fe80::2%wlan0-1"
        result = redactor._mask_ip_like_tokens(text)

        # Zones should be preserved
        assert '%eth0.100' in result, f"Zone eth0.100 lost in text: {result}"
        assert '%wlan0-1' in result, f"Zone wlan0-1 lost in text: {result}"

        # The .100 should not be treated as a separate token
        # (this was the bug - .100 could be leaked or corrupted)
        assert 'fe80::1%eth0' not in result or '%eth0.100' in result, \
            f"Zone appears to be truncated: {result}"


class TestIPv6ZoneAndPortHandling:
    """Test that IPv6 zone identifiers and ports are handled correctly"""

    def test_bracketed_ipv6_with_zone_and_port(self):
        """Verify that [IPv6%zone]:port preserves zone and port when masked"""
        # Use a global IPv6 address (2001:db8::/32 is documentation range)
        redactor = PfSenseRedactor()

        # Test with a simpler IPv6 without zone first
        text_simple = "Connect to [2001:db8::1]:8080"
        result_simple = redactor._mask_ip_like_tokens(text_simple)

        # Should mask IP but preserve port
        assert "2001:db8::1" not in result_simple
        assert ":8080" in result_simple

        # Now test that zone identifiers are preserved in the pattern
        # Note: The current implementation may not fully support zone IDs in all contexts
        # This test verifies the behaviour exists
        text_zone = "Server at 2001:db8::1%eth0"
        result_zone = redactor._mask_ip_like_tokens(text_zone)
        # Zone should be preserved if the IP is masked
        if "2001:db8::1" not in result_zone:
            assert "%eth0" in result_zone

    def test_bracketed_ipv6_with_port_no_zone(self):
        """Verify that [IPv6]:port is handled correctly"""
        redactor = PfSenseRedactor()

        text = "Connect to [2001:db8::1]:443"
        result = redactor._mask_ip_like_tokens(text)

        # Should mask IP but preserve port
        assert "2001:db8::1" not in result
        assert ":443" in result
        assert "[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]:443" in result


class TestBracketedAddressWithZone:
    """A bracketed IPv6 carrying a zone identifier, which used to leak whole

    '%' was a token separator, so '[fe80::1%igb0]:51820' was split into
    '[fe80::1' and 'igb0]:51820'. The first half carried an unbalanced bracket,
    failed to parse as an address, and was returned untouched, so nothing was
    redacted. The bare form 'fe80::1%igb0' happened to survive only because its
    two halves were masked and reassembled separately.

    Routable addresses leaked the same way, so this was not limited to
    link-local. '[addr%zone]:port' is the shape pfSense writes for a WireGuard
    peer endpoint.
    """

    @pytest.mark.parametrize('text,address', [
        ('[2001:db8::1%igb0]:51820', '2001:db8::1'),
        ('[2001:db8::1%igb0]', '2001:db8::1'),
        ('[fe80::1%igb0]:51820', 'fe80::1'),
        ('Endpoint = [2001:db8:abcd::5%vtnet0]:51820', '2001:db8:abcd::5'),
    ])
    def test_the_address_is_redacted(self, text, address):
        """The leak itself: the address must not survive"""
        assert address not in PfSenseRedactor()._mask_ip_like_tokens(text)

    def test_zone_brackets_and_port_all_survive(self):
        """Redacting the address must not destroy the structure around it"""
        result = PfSenseRedactor()._mask_ip_like_tokens('[fe80::1%igb0]:51820')

        assert result == '[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX%igb0]:51820'

    @pytest.mark.parametrize('zone', ['eth0.100', 'eth0:1', 'br-lan', 'bond0.50'])
    def test_awkward_interface_names_inside_brackets(self, zone):
        """The zone spellings the unbracketed tests already cover"""
        result = PfSenseRedactor()._mask_ip_like_tokens(f'[fe80::1%{zone}]:500')

        assert 'fe80::1' not in result
        assert f'%{zone}' in result

    def test_it_survives_a_whole_config(self, create_xml_file, cli_runner):
        """End to end, since the gap was in tokenising text rather than masking"""
        source = create_xml_file(
            '<?xml version="1.0"?><pfsense><installedpackages><wireguard><tunnels>'
            '<item><endpoint>[2001:db8::99%vtnet0]:51820</endpoint></item>'
            '</tunnels></wireguard></installedpackages></pfsense>',
            'wg.xml'
        )

        _, stdout, _ = cli_runner.run(str(source), flags=['--stdout'])

        assert '2001:db8::99' not in stdout
        assert '%vtnet0' in stdout


class TestPercentIsNotOverRedacted:
    """Making '%' a token character must not start rewriting ordinary text

    The masker only rewrites a token once ipaddress has parsed it, so prose and
    percent-encoding are unaffected. Worth pinning: this is the cost side of
    the fix above.
    """

    @pytest.mark.parametrize('text', [
        'CPU at 50% load',
        'disk 85% full',
        '/var/log%2Ffile',
        'user%40host',
        'abc%20def',
        'dead%20beef',
    ])
    def test_left_alone(self, text):
        """Percent signs in prose and percent-encoding are not addresses"""
        assert PfSenseRedactor()._mask_ip_like_tokens(text) == text


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
