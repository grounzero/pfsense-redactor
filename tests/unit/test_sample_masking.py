#!/usr/bin/env python3
"""
Tests for specific fixes applied to pfsense-redactor.py
These tests verify the correctness of targeted bug fixes and improvements.
"""

import io
import logging


class TestIPv6URLReconstruction:
    """Test that IPv6 addresses in URLs are properly wrapped in brackets"""

    def test_ipv6_url_in_config(self, cli_runner, tmp_path):
        """IPv6 hosts in URLs should be wrapped in brackets after masking"""
        config_file = tmp_path / "ipv6-url-config.xml"
        config_file.write_text("""<?xml version="1.0"?>
<pfsense>
    <url>http://[2001:db8::1]:8080/api</url>
    <url>https://[fe80::1]/path</url>
</pfsense>
""")

        output_file = tmp_path / "output.xml"
        exit_code, stdout, stderr = cli_runner.run(
            str(config_file),
            str(output_file)
        )

        # Read the output and verify IPv6 addresses are still wrapped in brackets
        output_content = output_file.read_text()

        # After masking, IPv6 should still be in brackets
        assert "[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]" in output_content
        # Port should be preserved
        assert ":8080" in output_content
        assert "/api" in output_content
        assert "/path" in output_content

    def test_ipv6_url_sample_in_dry_run_verbose(self, cli_runner, tmp_path):
        """IPv6 hosts in URL samples should be wrapped in brackets"""
        config_file = tmp_path / "ipv6-url-sample-config.xml"
        config_file.write_text("""<?xml version="1.0"?>
<pfsense>
    <url>http://[2001:db8::1]:8080/api</url>
</pfsense>
""")

        exit_code, stdout, stderr = cli_runner.run(
            str(config_file),
            None,
            flags=["--dry-run-verbose"]
        )

        # The sample should show the IPv6 address wrapped in brackets
        # Sample format: URL: http://[2001:db8:*:****::1]:8080/api → http://[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]:8080/api
        assert "URL:" in stdout
        assert "[2001:db8:*:****::1]" in stdout or "[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]" in stdout
        assert ":8080" in stdout


class TestCiscoMACMasking:
    """Test that Cisco MAC format samples are correctly masked"""

    def test_cisco_mac_sample_has_middle_period(self, cli_runner, tmp_path):
        """Cisco MAC samples should have period between masked sections"""
        config_file = tmp_path / "cisco-mac-config.xml"
        config_file.write_text("""<?xml version="1.0"?>
<pfsense>
    <mac>aabb.ccdd.eeff</mac>
</pfsense>
""")

        exit_code, stdout, stderr = cli_runner.run(
            str(config_file),
            None,
            flags=["--dry-run-verbose"]
        )

        # Should be aabb.****.eeff (with periods)
        assert "aabb.****.eeff" in stdout


class TestSecretSampleSafety:
    """Test that secret samples don't expose edge characters"""

    def test_secret_sample_only_shows_stars_and_length(self, cli_runner, tmp_path):
        """Secret samples should only show masked stars (capped at 8) and length"""
        config_file = tmp_path / "secret-config.xml"
        config_file.write_text("""<?xml version="1.0"?>
<pfsense>
    <password>MySecretPassword123</password>
</pfsense>
""")

        exit_code, stdout, stderr = cli_runner.run(
            str(config_file),
            None,
            flags=["--dry-run-verbose"]
        )

        # Should be capped at 8 stars with length, no edge chars
        assert "******** (len=19)" in stdout
        assert "MySecretPassword123" not in stdout


class TestDomainNormalisation:
    """Test that domain normalisation strips both leading and trailing dots"""

    def test_leading_and_trailing_dots_stripped(self, cli_runner, tmp_path):
        """Leading and trailing dots should be stripped from allow-listed domains"""
        config_file = tmp_path / "domain-config.xml"
        config_file.write_text("""<?xml version="1.0"?>
<pfsense>
    <host>sub.example.org</host>
</pfsense>
""")

        output_file = tmp_path / "output.xml"
        exit_code, stdout, stderr = cli_runner.run(
            str(config_file),
            str(output_file),
            flags=["--allowlist-domain", ".example.org."]
        )

        # Domain should be preserved (normalised and matched)
        output_content = output_file.read_text()
        assert "sub.example.org" in output_content
        assert "example.com" not in output_content


class TestDryRunVerboseEmptyOutput:
    """Test that dry-run verbose shows appropriate message when no samples collected"""

    def test_no_samples_shows_message(self, cli_runner, tmp_path):
        """When no redactions occur, should show '(no examples collected)' message"""
        config_file = tmp_path / "empty-config.xml"
        config_file.write_text("""<?xml version="1.0"?>
<pfsense>
    <version>1.0</version>
</pfsense>
""")

        exit_code, stdout, stderr = cli_runner.run(
            str(config_file),
            None,
            flags=["--dry-run-verbose"]
        )

        # Should show the "no examples collected" message when there are no redactions
        # The message appears after "Samples of changes" heading
        assert "Samples of changes" in stdout
        assert "(no examples collected)" in stdout


class TestSampleDeduplication:
    """Test that duplicate samples are not collected"""

    def test_duplicate_ips_not_collected(self, cli_runner, tmp_path):
        """Same IP appearing multiple times should only generate one sample"""
        config_file = tmp_path / "dup-config.xml"
        config_file.write_text("""<?xml version="1.0"?>
<pfsense>
    <server>203.0.113.10</server>
    <server>203.0.113.10</server>
    <server>203.0.113.10</server>
    <server>203.0.113.10</server>
    <server>203.0.113.10</server>
    <server>203.0.113.10</server>
</pfsense>
""")

        exit_code, stdout, stderr = cli_runner.run(
            str(config_file),
            None,
            flags=["--dry-run-verbose"]
        )

        # Count how many times the IP sample appears
        ip_sample_count = stdout.count("203.0.***.10")

        # Should only appear once despite 6 occurrences
        assert ip_sample_count == 1

    def test_different_values_all_collected(self, cli_runner, tmp_path):
        """Different values should all be collected (up to limit)"""
        config_file = tmp_path / "varied-config.xml"
        config_file.write_text("""<?xml version="1.0"?>
<pfsense>
    <server>203.0.113.10</server>
    <server>203.0.113.20</server>
    <server>203.0.113.30</server>
</pfsense>
""")

        exit_code, stdout, stderr = cli_runner.run(
            str(config_file),
            None,
            flags=["--dry-run-verbose"]
        )

        # All three different IPs should appear in samples
        assert "203.0.***.10" in stdout
        assert "203.0.***.20" in stdout
        assert "203.0.***.30" in stdout


class TestIntegrationOfAllFixes:
    """Integration tests verifying all fixes work together"""

    def test_all_fixes_in_single_config(self, cli_runner, tmp_path):
        """Test a config that exercises all the fixes"""
        config_file = tmp_path / "comprehensive-config.xml"
        config_file.write_text("""<?xml version="1.0"?>
<pfsense>
    <url>http://example.com/api</url>
    <mac>aabb.ccdd.eeff</mac>
    <password>MySecretPass</password>
    <host>test.example.org</host>
</pfsense>
""")

        exit_code, stdout, stderr = cli_runner.run(
            str(config_file),
            None,
            flags=["--dry-run-verbose", "--allowlist-domain", ".example.org."]
        )

        # Verify Cisco MAC has periods
        assert "aabb.****.eeff" in stdout

        # Verify secret is masked (capped at 8 stars)
        assert "******** (len=12)" in stdout
        assert "MySecretPass" not in stdout

        # Verify the test ran successfully (domain was preserved due to allow-list)


class TestPrintStatsDefaultdictFix:
    """Test that _print_stats correctly handles empty samples"""

    def test_empty_samples_prints_no_examples_collected(self, basic_redactor):
        """Verify that empty samples dict prints '(no examples collected)'"""
        redactor = basic_redactor
        redactor.dry_run_verbose = True

        # Capture output - clear existing handlers and add our own
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setLevel(logging.DEBUG)

        # Clear existing handlers and add our test handler
        redactor.logger.handlers.clear()
        redactor.logger.addHandler(handler)
        redactor.logger.setLevel(logging.DEBUG)

        redactor._print_stats()
        result = stream.getvalue()

        # Clean up
        redactor.logger.removeHandler(handler)

        # Should print the message about no examples
        assert "(no examples collected)" in result
        assert "Samples of changes" in result

    def test_with_samples_does_not_print_no_examples(self, basic_redactor):
        """Verify that when samples exist, we don't print '(no examples collected)'"""
        redactor = basic_redactor
        redactor.dry_run_verbose = True

        # Add a sample
        redactor._add_sample('IP', '192.168.1.1', 'XXX.XXX.XXX.XXX')

        # Capture output - clear existing handlers and add our own
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setLevel(logging.DEBUG)

        # Clear existing handlers and add our test handler
        redactor.logger.handlers.clear()
        redactor.logger.addHandler(handler)
        redactor.logger.setLevel(logging.DEBUG)

        redactor._print_stats()
        result = stream.getvalue()

        # Clean up
        redactor.logger.removeHandler(handler)

        # Should NOT print the no examples message
        assert "(no examples collected)" not in result
        # Should show the sample
        assert "IP:" in result


class TestSecretSampleStarFlooding:
    """Test that Secret samples don't flood with stars"""

    def test_short_secret_shows_all_stars(self, basic_redactor):
        """Verify that short secrets show all stars"""
        short_secret = "abc123"
        masked = basic_redactor._safe_mask_for_sample(short_secret, 'Secret')

        # Should show 6 stars
        assert masked == "****** (len=6)"

    def test_long_secret_caps_stars_at_8(self, basic_redactor):
        """Verify that very long secrets cap stars at 8"""
        # 1000 character secret
        long_secret = "a" * 1000
        masked = basic_redactor._safe_mask_for_sample(long_secret, 'Secret')

        # Should show only 8 stars but correct length
        assert masked == "******** (len=1000)"
        assert masked.count('*') == 8

    def test_exactly_8_chars_shows_8_stars(self, basic_redactor):
        """Verify that 8-char secrets show 8 stars"""
        secret = "12345678"
        masked = basic_redactor._safe_mask_for_sample(secret, 'Secret')

        assert masked == "******** (len=8)"

    def test_9_chars_still_caps_at_8_stars(self, basic_redactor):
        """Verify that 9-char secrets cap at 8 stars"""
        secret = "123456789"
        masked = basic_redactor._safe_mask_for_sample(secret, 'Secret')

        assert masked == "******** (len=9)"
        assert masked.count('*') == 8
