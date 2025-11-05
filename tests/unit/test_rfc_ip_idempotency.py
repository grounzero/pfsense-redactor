"""
Tests for RFC documentation IP idempotency in anonymisation mode.

Verifies that RFC 5737 IPv4 and RFC 3849 IPv6 documentation IPs generated
during anonymisation are not re-redacted on subsequent runs.
"""
import os
import tempfile
import xml.etree.ElementTree as ET
from pfsense_redactor.redactor import PfSenseRedactor


class TestRFCIPIdempotency:
    """Test that RFC documentation IPs are not re-redacted in anonymise mode"""

    def test_rfc_ips_in_urls_are_idempotent(self):
        """Verify RFC IPs in URLs are preserved on second pass"""
        test_config = '''<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>firewall</hostname>
    <domain>example.local</domain>
  </system>
  <installedpackages>
    <package>
      <url>http://10.1.1.1:8080/updates</url>
      <mirror>https://192.168.1.100/repo</mirror>
      <backup>ftp://172.16.0.50/backup</backup>
    </package>
  </installedpackages>
</pfsense>'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(test_config)
            input_file = f.name

        # First pass
        redactor1 = PfSenseRedactor(anonymise=True)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_file1 = f.name
        redactor1.redact_config(input_file, output_file1, dry_run=False, stdout_mode=False)

        tree1 = ET.parse(output_file1)
        root1 = tree1.getroot()
        url1 = root1.find('.//package/url').text
        mirror1 = root1.find('.//package/mirror').text
        backup1 = root1.find('.//package/backup').text

        # Second pass
        redactor2 = PfSenseRedactor(anonymise=True)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_file2 = f.name
        redactor2.redact_config(output_file1, output_file2, dry_run=False, stdout_mode=False)

        tree2 = ET.parse(output_file2)
        root2 = tree2.getroot()
        url2 = root2.find('.//package/url').text
        mirror2 = root2.find('.//package/mirror').text
        backup2 = root2.find('.//package/backup').text

        # Verify idempotency
        assert url1 == url2, "URL changed on second pass"
        assert mirror1 == mirror2, "Mirror changed on second pass"
        assert backup1 == backup2, "Backup changed on second pass"
        assert redactor2.stats['ips_redacted'] == 0, "IPs were re-redacted on second pass"

        # Verify RFC IPs were generated
        assert '192.0.2.' in url1 or '198.51.100.' in url1 or '203.0.113.' in url1

        # Clean up
        os.unlink(input_file)
        os.unlink(output_file1)
        os.unlink(output_file2)

    def test_rfc_ips_in_bare_text_are_idempotent(self):
        """Verify RFC IP aliases in bare text are preserved on second pass"""
        test_config = '''<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>8.8.8.8</dnsserver>
    <dnsserver2>1.1.1.1</dnsserver2>
    <gateway>10.0.0.1</gateway>
  </system>
</pfsense>'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(test_config)
            input_file = f.name

        # First pass
        redactor1 = PfSenseRedactor(anonymise=True)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_file1 = f.name
        redactor1.redact_config(input_file, output_file1, dry_run=False, stdout_mode=False)

        tree1 = ET.parse(output_file1)
        root1 = tree1.getroot()
        dns1 = root1.find('.//dnsserver').text
        dns2_1 = root1.find('.//dnsserver2').text
        gw1 = root1.find('.//gateway').text

        # Second pass
        redactor2 = PfSenseRedactor(anonymise=True)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_file2 = f.name
        redactor2.redact_config(output_file1, output_file2, dry_run=False, stdout_mode=False)

        tree2 = ET.parse(output_file2)
        root2 = tree2.getroot()
        dns1_2 = root2.find('.//dnsserver').text
        dns2_2 = root2.find('.//dnsserver2').text
        gw2 = root2.find('.//gateway').text

        # Verify idempotency
        assert dns1 == dns1_2, "DNS1 changed on second pass"
        assert dns2_1 == dns2_2, "DNS2 changed on second pass"
        assert gw1 == gw2, "Gateway changed on second pass"
        assert redactor2.stats['ips_redacted'] == 0, "IPs were re-redacted on second pass"

        # Verify IP_n format was used
        assert dns1.startswith('IP_')
        assert dns2_1.startswith('IP_')
        assert gw1.startswith('IP_')

        # Clean up
        os.unlink(input_file)
        os.unlink(output_file1)
        os.unlink(output_file2)

    def test_rfc_ips_in_original_config_are_preserved_in_anonymise_mode(self):
        """Verify RFC IPs in original config are preserved in anonymise mode (indistinguishable from generated)"""
        test_config = '''<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>192.0.2.1</dnsserver>
    <gateway>198.51.100.1</gateway>
    <ipv6>2001:db8::1</ipv6>
  </system>
</pfsense>'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(test_config)
            input_file = f.name

        # Redact with anonymise mode
        redactor = PfSenseRedactor(anonymise=True)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_file = f.name
        redactor.redact_config(input_file, output_file, dry_run=False, stdout_mode=False)

        tree = ET.parse(output_file)
        root = tree.getroot()
        dns = root.find('.//dnsserver').text
        gw = root.find('.//gateway').text
        ipv6 = root.find('.//ipv6').text

        # RFC IPs in original config are preserved (indistinguishable from our generated values)
        assert dns == '192.0.2.1', "RFC IPv4 should be preserved in anonymise mode"
        assert gw == '198.51.100.1', "RFC IPv4 should be preserved in anonymise mode"
        assert ipv6 == '2001:db8::1', "RFC IPv6 should be preserved in anonymise mode"
        assert redactor.stats['ips_redacted'] == 0, "RFC IPs should not be counted as redacted"

        # Clean up
        os.unlink(input_file)
        os.unlink(output_file)

    def test_mixed_rfc_and_real_ips_in_anonymise_mode(self):
        """Verify mixed RFC and real IPs are handled correctly"""
        test_config = '''<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>8.8.8.8</dnsserver>
    <gateway>192.0.2.1</gateway>
  </system>
</pfsense>'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(test_config)
            input_file = f.name

        # First pass - real IP gets converted, RFC IP preserved
        redactor1 = PfSenseRedactor(anonymise=True)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_file1 = f.name
        redactor1.redact_config(input_file, output_file1, dry_run=False, stdout_mode=False)

        tree1 = ET.parse(output_file1)
        root1 = tree1.getroot()
        dns1 = root1.find('.//dnsserver').text
        gw1 = root1.find('.//gateway').text

        # Real IP converted, RFC IP preserved
        assert dns1.startswith('IP_'), "Real IP should be converted to alias"
        assert gw1 == '192.0.2.1', "RFC IP should be preserved in anonymise mode"
        assert redactor1.stats['ips_redacted'] == 1, "Only real IP should be redacted"

        # Second pass - verify idempotency
        redactor2 = PfSenseRedactor(anonymise=True)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_file2 = f.name
        redactor2.redact_config(output_file1, output_file2, dry_run=False, stdout_mode=False)

        tree2 = ET.parse(output_file2)
        root2 = tree2.getroot()
        dns2 = root2.find('.//dnsserver').text
        gw2 = root2.find('.//gateway').text

        # Verify idempotency
        assert dns1 == dns2, "DNS changed on second pass"
        assert gw1 == gw2, "Gateway changed on second pass"
        assert redactor2.stats['ips_redacted'] == 0, "IPs were re-redacted on second pass"

        # Clean up
        os.unlink(input_file)
        os.unlink(output_file1)
        os.unlink(output_file2)

    def test_ipv6_rfc_ips_are_idempotent(self):
        """Verify RFC 3849 IPv6 documentation IPs are preserved on second pass"""
        test_config = '''<?xml version="1.0"?>
<pfsense>
  <system>
    <url>https://[2001:4860:4860::8888]:443/api</url>
  </system>
</pfsense>'''

        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write(test_config)
            input_file = f.name

        # First pass
        redactor1 = PfSenseRedactor(anonymise=True)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_file1 = f.name
        redactor1.redact_config(input_file, output_file1, dry_run=False, stdout_mode=False)

        tree1 = ET.parse(output_file1)
        root1 = tree1.getroot()
        url1 = root1.find('.//url').text

        # Second pass
        redactor2 = PfSenseRedactor(anonymise=True)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_file2 = f.name
        redactor2.redact_config(output_file1, output_file2, dry_run=False, stdout_mode=False)

        tree2 = ET.parse(output_file2)
        root2 = tree2.getroot()
        url2 = root2.find('.//url').text

        # Verify idempotency
        assert url1 == url2, "IPv6 URL changed on second pass"
        assert redactor2.stats['ips_redacted'] == 0, "IPv6 IPs were re-redacted on second pass"

        # Verify RFC 3849 IPv6 was generated
        assert '2001:db8::' in url1, "RFC 3849 IPv6 should be generated"

        # Clean up
        os.unlink(input_file)
        os.unlink(output_file1)
        os.unlink(output_file2)
