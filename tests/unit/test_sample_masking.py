#!/usr/bin/env python3
"""
Tests for specific fixes applied to pfsense-redactor.py
These tests verify the correctness of targeted bug fixes and improvements.
"""

import io
import logging

import pytest


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


class TestSampleMaskingNeverLeaksSecrets:
    """The --dry-run-verbose preview must not print credentials

    Users run --dry-run-verbose specifically to check what will happen before
    sharing a config. Its output goes to a terminal, and from there into CI
    logs and pasted tickets, so a live token printed here defeats the point.

    _mask_url_sample was previously untested (36 of its 44 statements) and
    passed the query string through verbatim.
    """

    SECRETS = (
        'SECRETTOKEN', 'Sup3rS3cret1', 'TOKEN99',
        'XiFdb92Kd8sM1nRq7vLwP3zY', 'IPV6SECRET',
    )

    def _assert_no_secret(self, masked):
        for secret in self.SECRETS:
            assert secret not in masked, f"sample display leaked {secret!r}: {masked}"

    def test_query_secret_not_shown(self, basic_redactor):
        """The demonstrated leak: query values printed in full"""
        masked = basic_redactor._safe_mask_for_sample(
            'https://api.example.com/v1?token=SECRETTOKEN', 'URL'
        )
        self._assert_no_secret(masked)

    def test_userinfo_password_not_shown(self, basic_redactor):
        """Userinfo password masking still works alongside the query fix"""
        masked = basic_redactor._safe_mask_for_sample(
            'https://ddnsuser:Sup3rS3cret1@members.dyndns.example/u?password=TOKEN99', 'URL'
        )
        self._assert_no_secret(masked)

    def test_path_token_not_shown(self, basic_redactor):
        """Webhook-style credentials live in the path, not the query"""
        masked = basic_redactor._safe_mask_for_sample(
            'https://hooks.example.com/services/T00/B00/XiFdb92Kd8sM1nRq7vLwP3zY', 'URL'
        )
        self._assert_no_secret(masked)

    def test_ipv6_branch_also_redacts_query(self, basic_redactor):
        """The bracketed-IPv6 branch builds the URL separately - check it too"""
        masked = basic_redactor._safe_mask_for_sample(
            'https://[2001:db8::1]:8443/p?apikey=IPV6SECRET', 'URL'
        )
        self._assert_no_secret(masked)

    def test_non_secret_query_preserved(self, basic_redactor):
        """Masking must stay useful: ordinary parameters still readable"""
        masked = basic_redactor._safe_mask_for_sample(
            'https://feeds.example.net/lists/blocklist?format=csv', 'URL'
        )
        assert 'format=csv' in masked

    def test_display_masking_does_not_inflate_stats(self, basic_redactor):
        """Sample display must have no redaction-counter side effects"""
        basic_redactor._safe_mask_for_sample(
            'https://api.example.com/v1?token=SECRETTOKEN', 'URL'
        )

        assert basic_redactor.stats['url_secrets_redacted'] == 0

    def test_malformed_url_returns_something_safe(self, basic_redactor):
        """A URL that will not parse must not raise, and must not leak"""
        masked = basic_redactor._safe_mask_for_sample('not a url at all', 'URL')

        assert isinstance(masked, str)

    def test_ip_host_url_masked(self, basic_redactor):
        """IPv4 literal hosts take a different branch to domains"""
        masked = basic_redactor._safe_mask_for_sample(
            'https://198.51.100.7/v1?token=SECRETTOKEN', 'URL'
        )
        self._assert_no_secret(masked)
        assert '198.51.100.7' not in masked

    def test_mac_sample_masks_middle_octets(self, basic_redactor):
        """Cover the MAC masker, previously exercised only via subprocess"""
        masked = basic_redactor._safe_mask_for_sample('aa:bb:cc:dd:ee:ff', 'MAC')

        assert masked.startswith('aa:bb:')
        assert 'cc:dd' not in masked

    def test_fqdn_sample_keeps_tld(self, basic_redactor):
        """FQDN masker keeps enough to be recognisable without full disclosure"""
        masked = basic_redactor._safe_mask_for_sample('host.internal.corp.example', 'FQDN')

        assert '***' in masked
        assert masked.endswith('corp.example')

    def test_ip_sample_masks_third_octet(self, basic_redactor):
        """IPv4 sample masker hides the third octet"""
        masked = basic_redactor._safe_mask_for_sample('192.0.2.55', 'IP')

        assert masked == '192.0.***.55'

    def test_unknown_category_returns_value_unchanged(self, basic_redactor):
        """Unknown categories fall through rather than raising"""
        assert basic_redactor._safe_mask_for_sample('plain', 'NoSuchCategory') == 'plain'


class TestMaskerFormatBranches:
    """Each address format the sample maskers dispatch to

    These branches existed before the maskers were split into a helper per
    format, and were untested then too - inlined in a nested conditional, they
    were simply harder to see. Covering them here so the split does not leave
    the same gap behind under a new name.
    """

    def test_ipv6_sample_keeps_the_ends(self, basic_redactor):
        """The v6 arm, which the v4 test above never reaches"""
        masked = basic_redactor._safe_mask_for_sample('2001:db8:1234:5678::abcd', 'IP')

        assert masked.startswith('2001:db8:')
        assert masked.endswith('abcd')
        assert '****' in masked

    def test_the_shortest_ipv6_is_still_masked(self, basic_redactor):
        """'::1' splits into three empty-ish groups, so it takes the normal path"""
        assert basic_redactor._safe_mask_for_sample('::1', 'IP') == '::*:****::1'

    @pytest.mark.parametrize('masker,value', [
        ('_mask_v6_sample', 'nocolons'),
        ('_mask_v4_sample', '1.2.3'),
    ])
    def test_group_count_guards_return_the_value(self, basic_redactor, masker, value):
        """Defensive guards, exercised directly because nothing else reaches them

        _mask_ip_sample only calls these once ipaddress has parsed the value, and
        no address it accepts can fail the group count: the shortest IPv6 is '::'
        which still splits into three. The guards stay because the maskers are
        reachable from _safe_mask_for_sample, which is handed whatever was
        redacted rather than a known-good address.
        """
        assert getattr(basic_redactor, masker)(value) == value

    def test_a_non_address_is_returned_unchanged(self, basic_redactor):
        """The masker is fed whatever was redacted, so it must not raise"""
        assert basic_redactor._safe_mask_for_sample('not-an-address', 'IP') == 'not-an-address'

    def test_dotted_cisco_mac(self, basic_redactor):
        """Three-group Cisco form takes the other branch from aa:bb:cc:dd:ee:ff"""
        masked = basic_redactor._safe_mask_for_sample('aabb.ccdd.eeff', 'MAC')

        assert masked == 'aabb.****.eeff'

    @pytest.mark.parametrize('value', ['aa:bb:cc', 'aabb.ccdd', 'nothing'])
    def test_malformed_macs_are_returned_unchanged(self, basic_redactor, value):
        """Wrong group counts fall through rather than being mangled"""
        assert basic_redactor._safe_mask_for_sample(value, 'MAC') == value


class TestZoneAndBracketsSurviveRedaction:
    """_restore_token_shape puts back what the token arrived with

    A zone identifier names a local interface and brackets are what make an
    IPv6 literal parseable inside a netloc, so both are structure rather than
    address and outlive the address they decorated.
    """

    def test_zone_identifier_is_preserved(self, basic_redactor):
        """fe80::1%igb0 keeps %igb0 after the address is masked"""
        result = basic_redactor.redact_text('fe80::1%igb0')

        assert '2001' not in result
        assert 'fe80::1' not in result, 'the address itself must go'
        assert '%igb0' in result, 'the interface name is structure, not address'

    def test_brackets_are_preserved(self, basic_redactor):
        """A bracketed literal stays bracketed, so the netloc still parses"""
        result = basic_redactor.redact_text('[2001:db8::1]:8080')

        assert '2001:db8::1' not in result, 'the address itself must go'
        assert result.startswith('[')
        assert result.endswith(']:8080')

    def test_both_together(self, basic_redactor):
        """Brackets, zone and port at once, which is the WireGuard peer shape

        This shape used to pass through redact_text untouched, because '%' was
        a token separator and the closing bracket was severed from the address.
        See tests/unit/test_ipv6_zone_identifiers.py for the full case.
        """
        result = basic_redactor.redact_text('[fe80::1%igb0]:51820')

        assert 'fe80::1' not in result
        assert '%igb0' in result
        assert result.startswith('[')
        assert result.endswith(']:51820')
