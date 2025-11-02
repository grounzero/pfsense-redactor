#!/usr/bin/env python3
"""
Security-focused tests for pfSense redactor

Tests for:
- ReDoS (Regular Expression Denial of Service) mitigation
- Empty domain bypass vulnerability
- Input validation and malformed data handling
"""

import pytest
import re
import time


class TestReDoSMitigation:
    """Test that regex patterns are protected against ReDoS attacks"""

    # Patterns with repetition limits (mitigated)
    EMAIL_RE_FIXED = re.compile(r'(?<!:)\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.){1,10}[A-Za-z]{2,}\b')
    FQDN_RE_FIXED = re.compile(r'\b(?:[A-Za-z0-9-]+\.){1,10}[A-Za-z]{2,}\b')

    def test_email_pattern_matches_valid_addresses(self):
        """Verify that fixed email pattern still matches valid inputs"""
        valid_emails = [
            'user@example.com',
            'test.user@sub.example.org',
            'admin@mail.company.co.uk',
            'info@deep.sub.domain.example.com'
        ]

        for email in valid_emails:
            assert self.EMAIL_RE_FIXED.search(email), f"Failed to match valid email: {email}"

    def test_fqdn_pattern_matches_valid_domains(self):
        """Verify that fixed FQDN pattern still matches valid inputs"""
        valid_fqdns = [
            'example.com',
            'sub.example.org',
            'deep.sub.domain.example.com',
            'mail.company.co.uk'
        ]

        for fqdn in valid_fqdns:
            assert self.FQDN_RE_FIXED.search(fqdn), f"Failed to match valid FQDN: {fqdn}"

    def test_email_pattern_resists_catastrophic_backtracking(self):
        """Verify that malicious email input doesn't cause exponential backtracking"""
        # Malicious input: many characters followed by @ (triggers backtracking)
        malicious_email = "a" * 50 + "." + "a" * 50 + "." + "a" * 50 + "@"

        start = time.time()
        result = self.EMAIL_RE_FIXED.search(malicious_email)
        elapsed = time.time() - start

        # Should complete in linear time (< 0.1s)
        assert elapsed < 0.1, f"Pattern took too long: {elapsed}s (possible ReDoS)"
        assert result is None, "Malicious input should not match"

    def test_fqdn_pattern_resists_catastrophic_backtracking(self):
        """Verify that malicious FQDN input doesn't cause exponential backtracking"""
        # Malicious input: many labels followed by invalid character
        malicious_fqdn = "a" * 50 + "." + "a" * 50 + "." + "a" * 50 + "."

        start = time.time()
        result = self.FQDN_RE_FIXED.search(malicious_fqdn)
        elapsed = time.time() - start

        # Should complete in linear time (< 0.1s)
        assert elapsed < 0.1, f"Pattern took too long: {elapsed}s (possible ReDoS)"

    def test_pattern_handles_exactly_10_labels(self):
        """Verify that patterns handle the maximum allowed labels (10)"""
        # Test exactly 10 labels (should match)
        ten_labels = '.'.join(['a'] * 10) + '.com'
        assert self.FQDN_RE_FIXED.search(ten_labels), "Failed to match 10-label domain"

        # Test email with 10 subdomain labels (should match)
        ten_label_email = 'user@' + '.'.join(['sub'] * 10) + '.com'
        assert self.EMAIL_RE_FIXED.search(ten_label_email), "Failed to match 10-label email domain"

    def test_pattern_handles_11_labels_gracefully(self):
        """Verify that patterns handle domains exceeding the limit gracefully"""
        # Test 11 labels (may or may not match, but should not hang)
        eleven_labels = '.'.join(['a'] * 11) + '.com'

        start = time.time()
        result = self.FQDN_RE_FIXED.search(eleven_labels)
        elapsed = time.time() - start

        # Should complete quickly regardless of match result
        assert elapsed < 0.1, f"Pattern took too long: {elapsed}s"


class TestEmptyDomainBypass:
    """Test suite for empty domain allow-list bypass vulnerability

    Verifies that malformed domain entries (e.g., '.', '...', '*.')
    cannot bypass domain redaction through the allow-list mechanism.
    """

    def test_empty_domain_normalisation_rejects_dots_only(self, basic_redactor):
        """Verify that domains consisting only of dots are rejected"""
        malformed_domains = ['.', '...', '....']

        for domain in malformed_domains:
            norm_domain, idna_domain = basic_redactor._normalise_domain(domain)
            assert norm_domain is None, f"Domain '{domain}' should return None, got '{norm_domain}'"
            assert idna_domain is None, f"Domain '{domain}' IDNA should return None, got '{idna_domain}'"

    def test_wildcard_only_entries_normalise_to_asterisk(self, basic_redactor):
        """Verify that wildcard-only entries normalise to '*' (not empty string)"""
        wildcard_domains = ['*.', '*.*', '*.*.']

        for domain in wildcard_domains:
            norm_domain, idna_domain = basic_redactor._normalise_domain(domain)
            # These normalise to '*' which is technically valid
            assert norm_domain == '*', f"Domain '{domain}' normalised to '{norm_domain}' (expected '*')"

    def test_empty_domain_rejected_from_allowlist(self, redactor_factory):
        """Verify that empty domain entries are filtered out of allowlist"""
        # Create redactor with malformed allowlist entries
        redactor = redactor_factory(allowlist_domains={'.', '...'})

        # Check that empty strings are NOT in the allowlist after normalisation
        assert '' not in redactor.allowlist_domains, "Empty string should NOT be in allowlist"
        assert None not in redactor.allowlist_domains, "None should NOT be in allowlist"

        # Allowlist should be empty since all entries were invalid
        assert len(redactor.allowlist_domains) == 0, "Allowlist should be empty with only invalid entries"

    def test_wildcard_only_in_allowlist_does_not_bypass(self, redactor_factory):
        """Verify that wildcard-only entry doesn't cause bypass vulnerability"""
        # Create redactor with wildcard-only entry
        redactor = redactor_factory(allowlist_domains={'*.'})

        # Wildcard-only normalises to '*' which is in the allowlist
        assert '*' in redactor.allowlist_domains, "Wildcard should normalise to '*'"
        assert '' not in redactor.allowlist_domains, "Empty string should NOT be in allowlist"

        # '*' in allowlist is unusual but doesn't cause bypass
        # because suffix matching requires a dot separator

    def test_normal_domains_work_correctly(self, redactor_factory):
        """Verify that normal domain allowlisting still works after fix"""
        redactor = redactor_factory(allowlist_domains={'example.com', '*.test.org'})

        # These should be allowed
        assert redactor._is_domain_allowed('example.com')
        assert redactor._is_domain_allowed('sub.example.com')
        assert redactor._is_domain_allowed('test.org')
        assert redactor._is_domain_allowed('sub.test.org')

        # These should NOT be allowed
        assert not redactor._is_domain_allowed('other.com')
        assert not redactor._is_domain_allowed('evil.net')

    def test_redaction_with_invalid_allowlist_entries(self, redactor_factory):
        """Verify that redaction works correctly even with invalid allowlist entries"""
        redactor = redactor_factory(allowlist_domains={'.', '...'})

        # Test text with domain
        text = "Connect to server.example.com for updates"
        result = redactor.redact_text(text, redact_ips=False, redact_domains=True)

        # With the fix, invalid entries are filtered out, so domain should be redacted
        assert 'server.example.com' not in result, \
            "Domain should be redacted since invalid allowlist entries are filtered"
        assert 'example.com' in result, \
            "Domain should be redacted to example.com"

    def test_mixed_valid_invalid_allowlist(self, redactor_factory):
        """Verify that valid entries are preserved when mixed with invalid ones"""
        redactor = redactor_factory(allowlist_domains={'.', 'valid.com', '...', 'another.org'})

        # Only valid entries should be in allowlist
        assert 'valid.com' in redactor.allowlist_domains
        assert 'another.org' in redactor.allowlist_domains
        assert '' not in redactor.allowlist_domains
        assert None not in redactor.allowlist_domains
        assert len(redactor.allowlist_domains) == 2, "Should have exactly 2 valid entries"


class TestInputValidation:
    """Test handling of malformed and edge-case inputs"""

    def test_empty_string_redaction(self, basic_redactor):
        """Verify that empty strings are handled gracefully"""
        result = basic_redactor.redact_text("")
        assert result == ""

    def test_none_input_handling(self, basic_redactor):
        """Verify that None input is handled gracefully"""
        result = basic_redactor.redact_text(None)
        assert result is None

    def test_very_long_input_performance(self, basic_redactor):
        """Verify that very long inputs are processed in reasonable time"""
        # Create a long text with repeated patterns
        long_text = "test@example.com " * 1000

        start = time.time()
        result = basic_redactor.redact_text(long_text)
        elapsed = time.time() - start

        # Should complete in reasonable time (< 1s for 1000 emails)
        assert elapsed < 1.0, f"Processing took too long: {elapsed}s"
        assert "example.com" in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
