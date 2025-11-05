"""
Tests for IP counter consistency in anonymization mode.

These tests verify that:
1. The same IP always maps to the same RFC documentation IP
2. IPv6 counters handle large values correctly (>65535)
"""

from pfsense_redactor.redactor import PfSenseRedactor


class TestIPCounterConsistency:
    """Test that IP counters are extracted correctly from aliases"""

    def test_same_ipv4_gets_consistent_rfc_ip(self):
        """Verify same IPv4 always maps to same RFC IP across multiple calls"""
        redactor = PfSenseRedactor(anonymise=True)

        ip1 = "10.0.0.1"
        ip2 = "10.0.0.2"

        # First call for ip1 - should get 192.0.2.1
        result1a = redactor._anonymise_ip_for_url(ip1, False)

        # First call for ip2 - should get 192.0.2.2
        result2 = redactor._anonymise_ip_for_url(ip2, False)

        # Second call for ip1 - should STILL get 192.0.2.1 (not 192.0.2.2!)
        result1b = redactor._anonymise_ip_for_url(ip1, False)

        assert result1a == "192.0.2.1", f"First call should map to 192.0.2.1, got {result1a}"
        assert result2 == "192.0.2.2", f"Second IP should map to 192.0.2.2, got {result2}"
        assert result1b == "192.0.2.1", f"Repeated call should still map to 192.0.2.1, got {result1b}"
        assert result1a == result1b, "Same IP must always map to same RFC IP"

    def test_same_ipv6_gets_consistent_rfc_ip(self):
        """Verify same IPv6 always maps to same RFC IP across multiple calls"""
        redactor = PfSenseRedactor(anonymise=True)

        ip1 = "2001:470::1"
        ip2 = "2001:470::2"

        # First call for ip1 - should get 2001:db8::1
        result1a = redactor._anonymise_ip_for_url(ip1, True)

        # First call for ip2 - should get 2001:db8::2
        result2 = redactor._anonymise_ip_for_url(ip2, True)

        # Second call for ip1 - should STILL get 2001:db8::1
        result1b = redactor._anonymise_ip_for_url(ip1, True)

        assert result1a == "2001:db8::1", f"First call should map to 2001:db8::1, got {result1a}"
        assert result2 == "2001:db8::2", f"Second IP should map to 2001:db8::2, got {result2}"
        assert result1b == "2001:db8::1", f"Repeated call should still map to 2001:db8::1, got {result1b}"
        assert result1a == result1b, "Same IP must always map to same RFC IP"

    def test_multiple_ips_maintain_stable_mapping(self):
        """Test that multiple IPs maintain stable mappings even after many operations"""
        redactor = PfSenseRedactor(anonymise=True)

        ips = [f"10.0.0.{i}" for i in range(1, 11)]

        # First pass: establish mappings
        first_pass = {ip: redactor._anonymise_ip_for_url(ip, False) for ip in ips}

        # Second pass: verify consistency
        second_pass = {ip: redactor._anonymise_ip_for_url(ip, False) for ip in ips}

        # Third pass: interleaved access
        third_pass = {}
        for ip in reversed(ips):  # Access in reverse order
            third_pass[ip] = redactor._anonymise_ip_for_url(ip, False)

        assert first_pass == second_pass, "Second pass should match first pass"
        assert first_pass == third_pass, "Third pass should match first pass"

        # Verify each IP has unique mapping
        assert len(set(first_pass.values())) == len(ips), "Each IP should have unique RFC IP"


class TestIPv6HextetOverflow:
    """Test that IPv6 RFC IPs handle large counter values correctly"""

    def test_ipv6_counter_within_single_hextet(self):
        """Test counters that fit in a single hextet (1-65535)"""
        redactor = PfSenseRedactor(anonymise=True)

        test_cases = [
            (1, "2001:db8::1"),
            (255, "2001:db8::ff"),
            (65535, "2001:db8::ffff"),  # Max single hextet
        ]

        for counter, expected in test_cases:
            result = redactor._counter_to_rfc_ip(counter, is_ipv6=True)
            assert result == expected, f"Counter {counter} should map to {expected}, got {result}"

    def test_ipv6_counter_exceeds_single_hextet(self):
        """Test counters that overflow to RFC 4193 ULA range after 65535"""
        redactor = PfSenseRedactor(anonymise=True)

        test_cases = [
            (65536, "fd00::0:1"),        # First overflow address
            (65537, "fd00::0:2"),        # Second overflow address
            (131070, "fd00::0:ffff"),    # Near boundary (offset 65534, hextet3 = 65535)
            (131071, "fd00::0:10000"),   # At boundary (offset 65535, hextet3 = 65536)
            (131072, "fd00::1:1"),       # After boundary (offset 65536, wraps to hextet2=1, hextet3=1)
        ]

        for counter, expected in test_cases:
            result = redactor._counter_to_rfc_ip(counter, is_ipv6=True)
            assert result == expected, f"Counter {counter} should map to {expected}, got {result}"

    def test_ipv6_very_large_counter(self):
        """Test very large counter values use RFC 4193 ULA range"""
        redactor = PfSenseRedactor(anonymise=True)

        # Test a large counter (e.g., 1 million)
        counter = 1_000_000
        result = redactor._counter_to_rfc_ip(counter, is_ipv6=True)

        # Counter 1000000 is in overflow range (> 65535)
        # overflow = 1000000 - 65535 = 934465
        # offset = 934464, hextet3 = (934464 % 65536) + 1 = 16961 (0x4241)
        # hextet2 = 934464 // 65536 = 14 (0xe)
        assert result == "fd00::e:4241", f"Counter {counter} should use ULA range, got {result}"

    def test_ipv6_counter_boundary_values(self):
        """Test boundary values around overflow point"""
        redactor = PfSenseRedactor(anonymise=True)

        # Test around the 65535/65536 boundary
        result_max_rfc = redactor._counter_to_rfc_ip(65535, is_ipv6=True)
        result_overflow = redactor._counter_to_rfc_ip(65536, is_ipv6=True)

        assert result_max_rfc == "2001:db8::ffff", "Max RFC value should be ::ffff"
        assert result_overflow == "fd00::0:1", "Should overflow to ULA range"

        # Verify they're different
        assert result_max_rfc != result_overflow, "Boundary values should produce different IPs"


class TestIPCounterInURLContext:
    """Test IP counter consistency specifically in URL contexts"""

    def test_url_with_repeated_ip_uses_consistent_rfc_ip(self):
        """Test that URLs with the same IP get consistent RFC IPs"""
        redactor = PfSenseRedactor(anonymise=True)

        # Process URLs directly (not through redact_text which uses IP_n for bare IPs)
        url1a = "http://10.0.0.1/path1"
        url2 = "http://10.0.0.2/path2"
        url1b = "http://10.0.0.1/path3"

        result1a = redactor._mask_url(url1a)
        result2 = redactor._mask_url(url2)
        result1b = redactor._mask_url(url1b)

        # Both occurrences of 10.0.0.1 should map to 192.0.2.1
        assert "192.0.2.1" in result1a, f"First URL should use 192.0.2.1, got {result1a}"
        assert "192.0.2.2" in result2, f"Second URL should use 192.0.2.2, got {result2}"
        assert "192.0.2.1" in result1b, f"Third URL should use 192.0.2.1, got {result1b}"

        # Verify the IP part is consistent (paths will differ)
        assert result1a == "http://192.0.2.1/path1", "First URL should have correct IP and path"
        assert result1b == "http://192.0.2.1/path3", "Third URL should have same IP, different path"

    def test_mixed_bare_and_url_ips_use_same_counter(self):
        """Test that bare IPs and IPs in URLs share the same counter system"""
        redactor = PfSenseRedactor(anonymise=True)

        # First encounter as bare IP
        bare_result = redactor._anonymise_ip("10.0.0.1")

        # Second encounter in URL context
        url_result = redactor._anonymise_ip_for_url("10.0.0.1", False)

        # Both should use counter 1
        assert bare_result == "IP_1", f"Bare IP should get IP_1 alias, got {bare_result}"
        assert url_result == "192.0.2.1", f"URL should use RFC IP 192.0.2.1, got {url_result}"

        # Verify they share the same underlying counter
        assert redactor.ip_aliases["10.0.0.1"] == "IP_1", "Should have IP_1 alias"
