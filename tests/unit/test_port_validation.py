"""
Tests for port validation in IP address parsing

Ensures that only valid ports (1-65535) are stripped from IP addresses,
whilst invalid ports are left as part of the token.
"""
import pytest
from pfsense_redactor.redactor import PfSenseRedactor


class TestPortValidation:  # pylint: disable=too-many-public-methods
    """Test port validation in IP address parsing"""

    @pytest.fixture
    def redactor(self):
        """Create a basic redactor instance"""
        return PfSenseRedactor()

    def test_valid_port_80(self, redactor):
        """Valid port 80 should be stripped and preserved"""
        result = redactor.redact_text('192.168.1.1:80')
        assert result == 'XXX.XXX.XXX.XXX:80'

    def test_valid_port_443(self, redactor):
        """Valid port 443 should be stripped and preserved"""
        result = redactor.redact_text('192.168.1.1:443')
        assert result == 'XXX.XXX.XXX.XXX:443'

    def test_valid_port_8080(self, redactor):
        """Valid port 8080 should be stripped and preserved"""
        result = redactor.redact_text('10.0.0.1:8080')
        assert result == 'XXX.XXX.XXX.XXX:8080'

    def test_valid_port_edge_case_1(self, redactor):
        """Valid port 1 (minimum) should be stripped and preserved"""
        result = redactor.redact_text('192.168.1.1:1')
        assert result == 'XXX.XXX.XXX.XXX:1'

    def test_valid_port_edge_case_65535(self, redactor):
        """Valid port 65535 (maximum) should be stripped and preserved"""
        result = redactor.redact_text('192.168.1.1:65535')
        assert result == 'XXX.XXX.XXX.XXX:65535'

    def test_invalid_port_0(self, redactor):
        """Invalid port 0 should NOT be stripped (reserved)"""
        result = redactor.redact_text('192.168.1.1:0')
        # Port 0 is invalid, so the entire token should be treated as-is
        # Since it doesn't match a valid IP pattern, it should remain unchanged
        assert result == '192.168.1.1:0'

    def test_invalid_port_65536(self, redactor):
        """Invalid port 65536 (>65535) should NOT be stripped"""
        result = redactor.redact_text('192.168.1.1:65536')
        # Port >65535 is invalid, so the entire token should remain unchanged
        assert result == '192.168.1.1:65536'

    def test_invalid_port_99999(self, redactor):
        """Invalid port 99999 (way over limit) should NOT be stripped"""
        result = redactor.redact_text('192.168.1.1:99999')
        assert result == '192.168.1.1:99999'

    def test_port_with_leading_zeros(self, redactor):
        """Port with leading zeros should be normalised"""
        result = redactor.redact_text('192.168.1.1:00080')
        # Leading zeros are stripped by int() conversion, resulting in port 80
        assert result == 'XXX.XXX.XXX.XXX:80'

    def test_port_with_many_leading_zeros(self, redactor):
        """Port with many leading zeros should be normalised"""
        result = redactor.redact_text('192.168.1.1:000000080')
        # Leading zeros are stripped by int() conversion, resulting in port 80
        assert result == 'XXX.XXX.XXX.XXX:80'

    def test_multiple_ips_with_ports(self, redactor):
        """Multiple IPs with ports should all be handled correctly"""
        text = '192.168.1.1:80 and 10.0.0.1:443 and 172.16.0.1:8080'
        result = redactor.redact_text(text)
        assert result == 'XXX.XXX.XXX.XXX:80 and XXX.XXX.XXX.XXX:443 and XXX.XXX.XXX.XXX:8080'

    def test_mixed_valid_invalid_ports(self, redactor):
        """Mix of valid and invalid ports should be handled correctly"""
        text = '192.168.1.1:80 192.168.1.2:0 192.168.1.3:65535 192.168.1.4:65536'
        result = redactor.redact_text(text)
        # Valid ports (80, 65535) are stripped and preserved
        # Invalid ports (0, 65536) cause the entire token to remain unchanged
        assert '192.168.1.2:0' in result
        assert '192.168.1.4:65536' in result
        assert 'XXX.XXX.XXX.XXX:80' in result
        assert 'XXX.XXX.XXX.XXX:65535' in result

    def test_port_on_private_ip_with_keep_private(self, redactor):
        """Port on private IP with keep_private_ips should preserve both"""
        redactor_keep = PfSenseRedactor(keep_private_ips=True)
        result = redactor_keep.redact_text('192.168.1.1:8080')
        assert result == '192.168.1.1:8080'

    def test_port_on_public_ip(self, redactor):
        """Port on public IP should redact IP but preserve port"""
        result = redactor.redact_text('8.8.8.8:53')
        assert result == 'XXX.XXX.XXX.XXX:53'

    def test_ipv6_with_brackets_and_port(self, redactor):
        """IPv6 with brackets and port should handle port correctly"""
        result = redactor.redact_text('[2001:db8::1]:8080')
        # IPv6 should be redacted, port preserved
        assert ':8080' in result
        assert '[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]:8080' in result

    def test_ipv6_with_brackets_and_invalid_port(self, redactor):
        """IPv6 with brackets and invalid port should not strip port"""
        result = redactor.redact_text('[2001:db8::1]:0')
        # Invalid port 0 should not be stripped, but IPv6 is still redacted
        # The entire token including :0 remains as-is since port is invalid
        assert ':0' in result

    def test_non_ip_with_port_like_suffix(self, redactor):
        """Non-IP tokens with port-like suffixes should not be affected"""
        result = redactor.redact_text('foo.bar.baz:8080')
        # This should be treated as a domain, not IP:port
        # The domain will be redacted to example.com, but the port-like suffix remains
        assert result == 'example.com:8080'

    def test_url_with_valid_port(self, redactor):
        """URL with valid port should preserve port"""
        result = redactor.redact_text('http://192.168.1.1:8080/path')
        assert ':8080' in result
        assert 'http://example.com:8080/path' in result

    def test_url_with_invalid_port(self, redactor):
        """URL with invalid port should handle gracefully"""
        # URL is processed, IP is masked, and invalid port is omitted
        result = redactor.redact_text('http://192.168.1.1:99999/path')
        # The key is that it doesn't crash and handles the invalid port gracefully
        # IP should be masked to example.com, invalid port omitted for security
        assert result == 'http://example.com/path'

    def test_anonymise_mode_with_valid_port(self, redactor):
        """Anonymise mode should preserve valid ports"""
        redactor_anon = PfSenseRedactor(anonymise=True)
        result = redactor_anon.redact_text('192.168.1.1:8080')
        # Should get IP_1:8080 or similar
        assert ':8080' in result
        assert 'IP_' in result

    def test_anonymise_mode_with_invalid_port(self, redactor):
        """Anonymise mode should not strip invalid ports"""
        redactor_anon = PfSenseRedactor(anonymise=True)
        result = redactor_anon.redact_text('192.168.1.1:0')
        # Invalid port should not be stripped
        assert '192.168.1.1:0' in result

    def test_port_normalisation_removes_leading_zeros(self, redactor):
        """Port normalisation should remove leading zeros"""
        result = redactor.redact_text('192.168.1.1:00443')
        # Should normalise to :443
        assert result == 'XXX.XXX.XXX.XXX:443'

    def test_edge_case_port_00001(self, redactor):
        """Port 00001 should normalise to 1"""
        result = redactor.redact_text('192.168.1.1:00001')
        assert result == 'XXX.XXX.XXX.XXX:1'

    def test_edge_case_port_065535(self, redactor):
        """Port 065535 should normalise to 65535"""
        result = redactor.redact_text('192.168.1.1:065535')
        # Leading zero is stripped by int() conversion
        assert result == 'XXX.XXX.XXX.XXX:65535'

    def test_security_port_0_not_stripped(self, redactor):
        """Security: Port 0 (reserved) should never be stripped"""
        # Port 0 is reserved and should not be treated as valid
        result = redactor.redact_text('10.0.0.1:0')
        assert '10.0.0.1:0' in result

    def test_security_port_overflow_not_stripped(self, redactor):
        """Security: Ports >65535 should never be stripped"""
        # Ports beyond valid range should not be stripped
        result = redactor.redact_text('10.0.0.1:100000')
        assert '10.0.0.1:100000' in result

    def test_common_ports_preserved(self, redactor):
        """Common service ports should be preserved correctly"""
        common_ports = [
            ('192.168.1.1:22', 'XXX.XXX.XXX.XXX:22'),    # SSH
            ('192.168.1.1:80', 'XXX.XXX.XXX.XXX:80'),    # HTTP
            ('192.168.1.1:443', 'XXX.XXX.XXX.XXX:443'),  # HTTPS
            ('192.168.1.1:3389', 'XXX.XXX.XXX.XXX:3389'), # RDP
            ('192.168.1.1:8080', 'XXX.XXX.XXX.XXX:8080'), # HTTP Alt
        ]
        for input_text, expected in common_ports:
            result = redactor.redact_text(input_text)
            assert result == expected, f"Failed for {input_text}"


class TestURLInvalidPortHandling:
    """Test invalid port handling in URLs (security fix)"""

    @pytest.fixture
    def redactor(self):
        """Create a basic redactor instance"""
        return PfSenseRedactor()

    def test_url_valid_port_preserved(self, redactor):
        """Valid port in URL should be preserved"""
        result = redactor.redact_text('http://testhost.com:8080/path')
        assert result == 'http://example.com:8080/path'

    def test_url_port_at_upper_boundary(self, redactor):
        """Port at upper boundary (65535) should be preserved"""
        result = redactor.redact_text('http://testhost.com:65535/path')
        assert result == 'http://example.com:65535/path'

    def test_url_port_out_of_range_high(self, redactor):
        """Port out of range (too high) should be omitted"""
        result = redactor.redact_text('http://testhost.com:99999/path')
        # Invalid port should be omitted, resulting in valid URL
        assert result == 'http://example.com/path'

    def test_url_port_zero_reserved(self, redactor):
        """Port zero (reserved) should be omitted"""
        result = redactor.redact_text('http://testhost.com:0/path')
        # Port 0 is invalid, should be omitted
        assert result == 'http://example.com/path'

    def test_url_non_numeric_port(self, redactor):
        """Non-numeric port should be omitted"""
        result = redactor.redact_text('http://testhost.com:abc/path')
        # Non-numeric port should be omitted
        assert result == 'http://example.com/path'

    def test_url_negative_port(self, redactor):
        """Negative port should be omitted"""
        result = redactor.redact_text('http://testhost.com:-1/path')
        # Negative port should be omitted
        assert result == 'http://example.com/path'

    def test_url_ipv6_with_invalid_port(self, redactor):
        """IPv6 URL with invalid port should omit port but preserve brackets"""
        result = redactor.redact_text('http://[2001:db8::1]:99999/path')
        # IPv6 should be redacted, invalid port omitted, brackets preserved
        assert result == 'http://[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]/path'

    def test_url_with_userinfo_and_invalid_port(self, redactor):
        """URL with userinfo and invalid port should omit port, redact password"""
        result = redactor.redact_text('http://user:pass@testhost.com:99999/path')
        # Credentials redacted, invalid port omitted
        assert result == 'http://user:REDACTED@example.com/path'

    def test_url_query_params_preserved_with_invalid_port(self, redactor):
        """Query params should be preserved when invalid port is omitted"""
        result = redactor.redact_text('http://testhost.com:99999/path?key=value')
        # Invalid port omitted, query params preserved
        assert result == 'http://example.com/path?key=value'

    def test_url_fragment_preserved_with_invalid_port(self, redactor):
        """Fragment should be preserved when invalid port is omitted"""
        result = redactor.redact_text('http://testhost.com:99999/path#section')
        # Invalid port omitted, fragment preserved
        assert result == 'http://example.com/path#section'

    def test_url_with_ip_and_invalid_port(self, redactor):
        """URL with IP host and invalid port should redact IP and omit port"""
        result = redactor.redact_text('http://192.168.1.1:99999/path')
        # IP redacted to example.com, invalid port omitted
        assert result == 'http://example.com/path'

    def test_multiple_urls_mixed_valid_invalid_ports(self, redactor):
        """Multiple URLs with mixed valid/invalid ports"""
        text = 'http://host1.com:8080/path http://host2.com:99999/path http://host3.com:443/path'
        result = redactor.redact_text(text)
        # Valid ports preserved, invalid omitted
        assert 'http://example.com:8080/path' in result
        assert 'http://example.com/path' in result  # Invalid port omitted
        assert 'http://example.com:443/path' in result

    def test_url_anonymise_mode_with_invalid_port(self, redactor):
        """Anonymise mode should omit invalid ports in URLs"""
        redactor_anon = PfSenseRedactor(anonymise=True)
        result = redactor_anon.redact_text('http://test.com:99999/path')
        # Domain anonymised, invalid port omitted
        assert ':99999' not in result
        assert 'domain' in result and '.example/path' in result

    def test_url_with_port_leading_zeros_valid(self, redactor):
        """URL with port having leading zeros (valid range) should normalise"""
        result = redactor.redact_text('http://testhost.com:00080/path')
        # Leading zeros stripped, port 80 preserved
        assert result == 'http://example.com:80/path'

    def test_url_https_with_invalid_port(self, redactor):
        """HTTPS URL with invalid port should omit port"""
        result = redactor.redact_text('https://testhost.com:99999/secure')
        assert result == 'https://example.com/secure'

    def test_url_ftp_with_invalid_port(self, redactor):
        """FTP URL with invalid port should omit port"""
        result = redactor.redact_text('ftp://testhost.com:99999/file')
        assert result == 'ftp://example.com/file'

    def test_url_no_regression_valid_ports(self, redactor):
        """Ensure no regression: valid ports still work correctly"""
        test_cases = [
            ('http://testhost.com:80/path', 'http://example.com:80/path'),
            ('http://testhost.com:443/path', 'http://example.com:443/path'),
            ('http://testhost.com:8080/path', 'http://example.com:8080/path'),
            ('http://testhost.com:1/path', 'http://example.com:1/path'),
            ('http://testhost.com:65535/path', 'http://example.com:65535/path'),
        ]
        for input_url, expected in test_cases:
            result = redactor.redact_text(input_url)
            assert result == expected, f"Regression for {input_url}"

    def test_url_invalid_port_no_crash(self, redactor):
        """Invalid ports should not cause crashes"""
        # These should all be handled gracefully without exceptions
        test_cases = [
            ('http://testhost.com:999999/path', 'http://example.com/path'),
            ('http://testhost.com:0/path', 'http://example.com/path'),
            ('http://testhost.com:-1/path', 'http://example.com/path'),
            ('http://testhost.com:abc/path', 'http://example.com/path'),
            ('http://testhost.com:12.34/path', 'http://example.com/path'),
        ]
        for url, expected in test_cases:
            result = redactor.redact_text(url)
            # Should not crash, and should produce valid output with exact match
            assert result == expected, f"Failed for {url}: got {result}"
