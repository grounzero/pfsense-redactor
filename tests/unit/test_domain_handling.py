#!/usr/bin/env python3
"""
Domain handling tests

Tests for domain normalisation, IDNA support, and domain allowlisting
"""

import pytest


class TestAnonymiseDomainIDNA:
    """Test that _anonymise_domain correctly handles IDNA/punycode"""

    def test_unicode_and_punycode_get_same_alias(self, redactor_factory):
        """Verify that Unicode and punycode forms of same domain get same alias"""
        redactor = redactor_factory(anonymise=True)

        # bücher.de in Unicode and punycode
        unicode_domain = "bücher.de"
        punycode_domain = "xn--bcher-kva.de"

        alias1 = redactor._anonymise_domain(unicode_domain)
        alias2 = redactor._anonymise_domain(punycode_domain)

        # Should get the same alias
        assert alias1 == alias2
        assert alias1.startswith("domain")
        assert alias1.endswith(".example")

    def test_different_domains_get_different_aliases(self, redactor_factory):
        """Verify that different domains get different aliases"""
        redactor = redactor_factory(anonymise=True)

        alias1 = redactor._anonymise_domain("example.com")
        alias2 = redactor._anonymise_domain("test.org")

        assert alias1 != alias2

    def test_case_insensitive_aliasing(self, redactor_factory):
        """Verify that domain aliasing is case-insensitive"""
        redactor = redactor_factory(anonymise=True)

        alias1 = redactor._anonymise_domain("Example.COM")
        alias2 = redactor._anonymise_domain("example.com")

        assert alias1 == alias2

    def test_trailing_dots_normalised(self, redactor_factory):
        """Verify that trailing dots are normalised"""
        redactor = redactor_factory(anonymise=True)

        alias1 = redactor._anonymise_domain("example.com.")
        alias2 = redactor._anonymise_domain("example.com")

        assert alias1 == alias2


class TestDomainAllowlistIDNA:
    """Test domain allowlist with IDNA support"""

    def test_unicode_domain_in_allowlist_preserved(self, redactor_factory):
        """Verify that Unicode domains in allowlist are preserved"""
        domains = {'bücher.de'}
        redactor = redactor_factory(allowlist_domains=domains)

        text = "Visit bücher.de for books"
        result = redactor.redact_text(text)

        # Domain should be preserved
        assert "bücher.de" in result

    def test_punycode_form_also_preserved(self, redactor_factory):
        """Verify that punycode form is also preserved when Unicode is in allowlist"""
        domains = {'bücher.de'}
        redactor = redactor_factory(allowlist_domains=domains)

        # Use punycode form in text
        text = "Visit xn--bcher-kva.de for books"
        result = redactor.redact_text(text)

        # Punycode form should be preserved
        assert "xn--bcher-kva.de" in result

    def test_suffix_matching_works_with_idna(self, redactor_factory):
        """Verify that suffix matching works with IDNA domains"""
        domains = {'example.org'}
        redactor = redactor_factory(allowlist_domains=domains)

        text = "Visit api.sub.example.org"
        result = redactor.redact_text(text)

        # Subdomain should be preserved
        assert "api.sub.example.org" in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
