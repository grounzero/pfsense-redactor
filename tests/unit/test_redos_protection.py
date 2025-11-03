"""
Test ReDoS (Regular Expression Denial of Service) protection
"""
import time
from pfsense_redactor.redactor import PfSenseRedactor


class TestReDoSProtection:
    """Test that regex patterns don't hang on pathological input"""

    def test_url_redos_protection(self):
        """Ensure URL regex doesn't hang on pathological input"""
        redactor = PfSenseRedactor()

        # Pathological input: almost-URL with 100k chars
        pathological = "https://" + "a" * 100000 + " normal text"

        start = time.time()
        result = redactor.redact_text(pathological, redact_domains=True)
        elapsed = time.time() - start

        # Should complete quickly (< 1 second)
        assert elapsed < 1.0, f"ReDoS detected: took {elapsed:.2f}s"

        # Should preserve non-URL text
        assert "normal text" in result

    def test_email_redos_protection(self):
        """Ensure email regex doesn't hang on pathological input"""
        redactor = PfSenseRedactor()

        pathological = "a" * 100000 + "@example.com"

        start = time.time()
        result = redactor.redact_text(pathological, redact_domains=True)
        elapsed = time.time() - start

        assert elapsed < 1.0, f"ReDoS detected: took {elapsed:.2f}s"

    def test_fqdn_redos_protection(self):
        """Ensure FQDN regex doesn't hang on pathological input"""
        redactor = PfSenseRedactor()

        pathological = ("subdomain." * 1000) + "example.com"

        start = time.time()
        result = redactor.redact_text(pathological, redact_domains=True)
        elapsed = time.time() - start

        assert elapsed < 1.0, f"ReDoS detected: took {elapsed:.2f}s"

    def test_legitimate_urls_still_work(self):
        """Ensure legitimate URLs are still properly redacted"""
        redactor = PfSenseRedactor()

        text = "Visit https://firmware.netgate.com for updates"
        result = redactor.redact_text(text, redact_domains=True)

        # Verify URL was redacted (not URL sanitization - this is a redaction tool test)
        assert result == "Visit https://example.com for updates"
        assert "netgate.com" not in result

    def test_legitimate_emails_still_work(self):
        """Ensure legitimate emails are still properly redacted"""
        redactor = PfSenseRedactor()

        text = "Contact admin@example.org for help"
        result = redactor.redact_text(text, redact_domains=True)

        # Verify email was redacted (not URL sanitization - this is a redaction tool test)
        assert result == "Contact user@example.com for help"
        assert "admin@example.org" not in result

    def test_legitimate_fqdns_still_work(self):
        """Ensure legitimate FQDNs are still properly redacted"""
        redactor = PfSenseRedactor()

        text = "Server at server.example.org"
        result = redactor.redact_text(text, redact_domains=True)

        # Verify the domain was redacted (not URL sanitization - this is a redaction tool test)
        assert result == "Server at example.com"
        assert "server.example.org" not in result

    def test_max_text_chunk_protection(self):
        """Ensure absurdly long text chunks are truncated"""
        redactor = PfSenseRedactor()

        # Create text larger than MAX_TEXT_CHUNK (1MB)
        huge_text = "a" * (redactor.MAX_TEXT_CHUNK + 1000)

        result = redactor.redact_text(huge_text, redact_domains=True)

        # Should be truncated to MAX_TEXT_CHUNK
        assert len(result) <= redactor.MAX_TEXT_CHUNK

    def test_url_length_limit(self):
        """Ensure URLs longer than MAX_URL_LENGTH are skipped"""
        redactor = PfSenseRedactor()

        # Create a URL-like string longer than MAX_URL_LENGTH
        long_url = "https://" + "a" * (redactor.MAX_URL_LENGTH + 100) + ".com"

        result = redactor.redact_text(long_url, redact_domains=True)

        # Should be unchanged (too long to process)
        assert long_url in result

    def test_email_length_limit(self):
        """Ensure emails longer than MAX_EMAIL_LENGTH are skipped"""
        redactor = PfSenseRedactor()

        # Create an email-like string longer than MAX_EMAIL_LENGTH
        long_email = "a" * (redactor.MAX_EMAIL_LENGTH + 100) + "@example.com"

        result = redactor.redact_text(long_email, redact_domains=True)

        # Should be unchanged (too long to process)
        assert long_email in result

    def test_fqdn_length_limit(self):
        """Ensure FQDNs longer than MAX_FQDN_LENGTH are skipped"""
        redactor = PfSenseRedactor()

        # Create an FQDN-like string longer than MAX_FQDN_LENGTH
        long_fqdn = "a" * (redactor.MAX_FQDN_LENGTH + 100) + ".com"

        result = redactor.redact_text(long_fqdn, redact_domains=True)

        # Should be unchanged (too long to process)
        assert long_fqdn in result


class TestExceptionHandling:
    """Test that exception handling is specific and correct"""

    def test_idna_encode_normal_domains(self):
        """Test IDNA encoding works for normal domains"""
        from pfsense_redactor.redactor import _idna_encode

        assert _idna_encode("example.com") == "example.com"
        assert _idna_encode("bücher.de") == "xn--bcher-kva.de"

    def test_idna_encode_malformed_domains(self):
        """Test IDNA encoding handles malformed domains gracefully"""
        from pfsense_redactor.redactor import _idna_encode

        # Should not crash on malformed input
        assert _idna_encode("") == ""
        assert _idna_encode("...") == "..."

        # Should handle edge cases
        result = _idna_encode("invalid\x00domain")
        assert result is not None  # Should return something, not crash
