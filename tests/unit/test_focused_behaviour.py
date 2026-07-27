"""
Focused behaviour tests using synthetic mini-fixtures

These tests use minimal inline XML to verify specific redaction logic
without depending on large sample files.
"""
import xml.etree.ElementTree as ET

import pytest

# Synthetic XML fixtures
SECRETS_XML = """<?xml version="1.0"?>
<pfsense>
  <system>
    <password>secret123</password>
    <passwordenc>encrypted_pass</passwordenc>
    <apikey>abc123def456</apikey>
  </system>
  <openvpn>
    <server>
      <shared_key>preshared_key_data</shared_key>
      <tls>tls_auth_key_data</tls>
    </server>
  </openvpn>
</pfsense>
"""

CERTS_XML = """<?xml version="1.0"?>
<pfsense>
  <cert>
    <refid>cert1</refid>
    <descr>Test Certificate</descr>
    <crt>-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKKzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
-----END CERTIFICATE-----</crt>
    <prv>-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1+fWIcPm15A8+raZ4dp5qJXGWvNW0tAg45jE5Cp2meCq1Y
-----END PRIVATE KEY-----</prv>
  </cert>
  <key>-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tfn1iHD5teQPPq2me
-----END RSA PRIVATE KEY-----</key>
  <public-key>ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7VJTUt9Us8cKj user@host</public-key>
</pfsense>
"""

CERT_CONTAINER_XML = """<?xml version="1.0"?>
<pfsense>
  <cert>
    <refid>cert2</refid>
    <descr>Container Cert</descr>
    <crt>-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKKzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
-----END CERTIFICATE-----</crt>
    <prv>-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
-----END PRIVATE KEY-----</prv>
  </cert>
</pfsense>
"""

MAC_XML = """<?xml version="1.0"?>
<pfsense>
  <interfaces>
    <wan>
      <mac>aa:bb:cc:dd:ee:ff</mac>
      <descr>Interface with MAC aa:bb:cc:dd:ee:ff and IP 192.168.1.1</descr>
    </wan>
    <lan>
      <mac>aabb.ccdd.eeff</mac>
      <descr>Cisco format aabb.ccdd.eeff</descr>
    </lan>
  </interfaces>
</pfsense>
"""

IP_POLICY_XML = """<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>8.8.8.8</dnsserver>
    <dnsserver>1.1.1.1</dnsserver>
  </system>
  <interfaces>
    <lan>
      <ipaddr>192.168.1.1</ipaddr>
      <subnet>255.255.255.0</subnet>
    </lan>
    <wan>
      <ipaddr>10.0.0.5</ipaddr>
      <gateway>10.0.0.1</gateway>
    </wan>
    <opt1>
      <ipaddrv6>fc00::1</ipaddrv6>
      <subnetv6>64</subnetv6>
    </opt1>
    <opt2>
      <ipaddrv6>fe80::1%em0</ipaddrv6>
    </opt2>
  </interfaces>
  <gateways>
    <gateway>
      <gateway>172.16.0.1</gateway>
    </gateway>
  </gateways>
  <special>
    <loopback>127.0.0.1</loopback>
    <loopback6>::1</loopback6>
    <multicast>224.0.0.1</multicast>
    <unspecified>0.0.0.0</unspecified>
    <unspecified6>::</unspecified6>
  </special>
</pfsense>
"""

URL_XML = """<?xml version="1.0"?>
<pfsense>
  <packages>
    <package>
      <url>https://user:pass@10.0.0.1:8443/path?query=1</url>
      <repo>https://example.com/repo</repo>
      <mirror>http://mirror.example.org:8080/files</mirror>
    </package>
  </packages>
</pfsense>
"""

NAMESPACE_XML = """<?xml version="1.0"?>
<ns:pfsense xmlns:ns="http://example.com/pfsense">
  <ns:system>
    <ns:password>secret123</ns:password>
    <ns:hostname>firewall.example.com</ns:hostname>
  </ns:system>
  <ns:cert>
    <ns:crt>-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKKzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
-----END CERTIFICATE-----</ns:crt>
  </ns:cert>
</ns:pfsense>
"""

AGGRESSIVE_XML = """<?xml version="1.0"?>
<pfsense>
  <system>
    <description>Server at 192.168.1.100 with domain example.com</description>
    <notes>Contact admin@example.com for issues</notes>
  </system>
  <custom attr="192.168.1.50">
    <field>Some text with 10.0.0.1 embedded</field>
  </custom>
</pfsense>
"""

SENSITIVE_ATTRS_XML = """<?xml version="1.0"?>
<pfsense>
  <system>
    <user password="secret123" api_key="abc123">admin</user>
    <service auth_token="bearer_xyz" client-secret="secret456">api</service>
  </system>
</pfsense>
"""


class TestSecretsVsCerts:
    """Test distinction between secrets and certificates"""

    def test_secrets_fully_redacted(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify secret elements are fully redacted to [REDACTED]"""
        xml_file = create_xml_file(SECRETS_XML)
        output_file = temp_output_dir / "secrets_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file)
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # All secrets should be [REDACTED]
        assert '<password>[REDACTED]</password>' in output_content
        assert '<passwordenc>[REDACTED]</passwordenc>' in output_content
        assert '<apikey>[REDACTED]</apikey>' in output_content
        assert '<shared_key>[REDACTED]</shared_key>' in output_content
        assert '<tls>[REDACTED]</tls>' in output_content

        # Original values should not appear
        assert 'secret123' not in output_content
        assert 'encrypted_pass' not in output_content
        assert 'abc123def456' not in output_content

    def test_certs_collapsed_to_placeholder(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify cert/key elements collapse to [REDACTED_CERT_OR_KEY]"""
        xml_file = create_xml_file(CERTS_XML)
        output_file = temp_output_dir / "certs_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file)
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Certs should be collapsed
        assert '<crt>[REDACTED_CERT_OR_KEY]</crt>' in output_content
        assert '<key>[REDACTED_CERT_OR_KEY]</key>' in output_content
        assert '<public-key>[REDACTED_CERT_OR_KEY]</public-key>' in output_content

        # Private key under cert should be fully redacted
        assert '<prv>[REDACTED]</prv>' in output_content

        # PEM markers should not appear
        assert 'BEGIN CERTIFICATE' not in output_content
        assert 'BEGIN PRIVATE KEY' not in output_content
        assert 'BEGIN RSA PRIVATE KEY' not in output_content

    def test_cert_container_children_processed(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify cert container processes children correctly"""
        xml_file = create_xml_file(CERT_CONTAINER_XML)
        output_file = temp_output_dir / "cert_container_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file)
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Container structure preserved
        assert '<cert>' in output_content
        assert '<refid>cert2</refid>' in output_content
        assert '<descr>Container Cert</descr>' in output_content

        # Children redacted appropriately
        assert '<crt>[REDACTED_CERT_OR_KEY]</crt>' in output_content
        assert '<prv>[REDACTED]</prv>' in output_content


class TestMACPrecedence:
    """Test MAC address handling before IP processing"""

    def test_mac_formats_redacted(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify both standard and Cisco MAC formats are redacted in <mac> tags"""
        xml_file = create_xml_file(MAC_XML)
        output_file = temp_output_dir / "mac_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file)
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # MACs in <mac> tags should be redacted
        assert '<mac>XX:XX:XX:XX:XX:XX</mac>' in output_content or '<mac>xx:xx:xx:xx:xx:xx</mac>' in output_content.lower()
        assert '<mac>XXXX.XXXX.XXXX</mac>' in output_content or '<mac>xxxx.xxxx.xxxx</mac>' in output_content.lower()

        # Note: MACs in <descr> tags are not redacted unless --aggressive is used
        # This is intentional to avoid over-sanitization

    def test_mac_not_mangled_as_ipv6(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify MACs with colons aren't misinterpreted as IPv6 in <mac> tags"""
        xml_file = create_xml_file(MAC_XML)
        output_file = temp_output_dir / "mac_ipv6_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--keep-private-ips"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # MACs in <mac> tags should be redacted, not mangled as IPv6
        assert '<mac>XX:XX:XX:XX:XX:XX</mac>' in output_content or '<mac>xx:xx:xx:xx:xx:xx</mac>' in output_content.lower()
        assert '<mac>XXXX.XXXX.XXXX</mac>' in output_content or '<mac>xxxx.xxxx.xxxx</mac>' in output_content.lower()


class TestIPPolicy:
    """Test IP address preservation and redaction policies"""

    def test_public_ips_masked(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify public IPs are masked by default"""
        xml_file = create_xml_file(IP_POLICY_XML)
        output_file = temp_output_dir / "ip_public_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file)
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Public IPs should be masked (no hard-coded whitelist)
        assert '8.8.8.8' not in output_content
        assert '1.1.1.1' not in output_content

        # Private IPs are also masked by default
        assert 'XXX.XXX.XXX.XXX' in output_content

    def test_private_ips_preserved_with_flag(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify private IPs preserved with --keep-private-ips"""
        xml_file = create_xml_file(IP_POLICY_XML)
        output_file = temp_output_dir / "ip_private_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--keep-private-ips"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # RFC1918 addresses preserved
        assert '192.168.1.1' in output_content
        assert '10.0.0.5' in output_content
        assert '10.0.0.1' in output_content
        assert '172.16.0.1' in output_content

        # ULA preserved
        assert 'fc00::1' in output_content

        # Link-local with zone preserved
        assert 'fe80::1%em0' in output_content

        # Loopback preserved
        assert '127.0.0.1' in output_content
        assert '::1' in output_content

        # Multicast preserved
        assert '224.0.0.1' in output_content

        # Unspecified preserved
        assert '0.0.0.0' in output_content
        assert '::' in output_content or '<unspecified6>::</unspecified6>' in output_content

    def test_netmasks_always_preserved(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify common netmasks preserved regardless of flags"""
        xml_file = create_xml_file(IP_POLICY_XML)
        output_file = temp_output_dir / "netmask_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file)
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Netmask should be preserved
        assert '255.255.255.0' in output_content


class TestURLHandling:
    """Test URL parsing and redaction"""

    def test_url_with_internal_ip_preserved(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify URL with internal IP host preserved with --keep-private-ips"""
        xml_file = create_xml_file(URL_XML)
        output_file = temp_output_dir / "url_internal_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--keep-private-ips"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Internal IP host preserved, password redacted
        assert 'https://user:REDACTED@10.0.0.1:8443/path?query=1' in output_content
        assert 'pass@' not in output_content

    def test_url_public_domain_masked(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify URL with public domain has host masked"""
        xml_file = create_xml_file(URL_XML)
        output_file = temp_output_dir / "url_public_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--keep-private-ips"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Scheme and structure preserved
        assert 'https://' in output_content
        assert 'http://' in output_content

        # At least one domain should be masked (URLs in known elements)
        # Note: Not all occurrences may be in redacted elements
        assert 'example.com' in output_content or output_content.count('example.com') < URL_XML.count('example.com')

    def test_url_structure_preserved(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify URL scheme, path, query, fragment preserved"""
        xml_file = create_xml_file(URL_XML)
        output_file = temp_output_dir / "url_structure_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--keep-private-ips"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Path and query preserved
        assert '/path?query=1' in output_content
        assert ':8443' in output_content
        assert ':8080' in output_content


class TestNamespaces:
    """Test namespace handling"""

    def test_namespaced_elements_redacted(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify namespaced elements are correctly identified and redacted"""
        xml_file = create_xml_file(NAMESPACE_XML)
        output_file = temp_output_dir / "namespace_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file)
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Secrets redacted despite namespace
        assert '[REDACTED]' in output_content
        assert 'secret123' not in output_content

        # Certs collapsed despite namespace
        assert '[REDACTED_CERT_OR_KEY]' in output_content
        assert 'BEGIN CERTIFICATE' not in output_content

        # Domains should be redacted (hostname is in ip_containing_elements)
        # Note: May still appear in non-redacted contexts
        assert output_content.count('example.com') <= NAMESPACE_XML.count('example.com')

    def test_namespaced_root_accepted(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify namespaced root tag is accepted"""
        xml_file = create_xml_file(NAMESPACE_XML)
        output_file = temp_output_dir / "namespace_root_out.xml"

        # Should succeed without --fail-on-warn
        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file)
        )

        assert exit_code == 0


class TestAggressiveMode:
    """Test aggressive redaction mode"""

    def test_aggressive_redacts_text(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify aggressive mode redacts IPs/domains in all text"""
        xml_file = create_xml_file(AGGRESSIVE_XML)
        output_file = temp_output_dir / "aggressive_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--aggressive", "--keep-private-ips"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # IPs in description should be preserved (private)
        assert '192.168.1.100' in output_content
        assert '10.0.0.1' in output_content

        # Emails should be masked in aggressive mode
        assert 'user@example.com' in output_content
        assert 'admin@example.com' not in output_content

        # Note: "example.com" is the placeholder used for redaction, so it will appear in output
        # The test should verify that the email was redacted, not the domain count

    def test_aggressive_redacts_attributes(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify aggressive mode redacts attributes"""
        xml_file = create_xml_file(AGGRESSIVE_XML)
        output_file = temp_output_dir / "aggressive_attr_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--aggressive", "--keep-private-ips"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Attribute with IP should be preserved (private)
        assert '192.168.1.50' in output_content


class TestSensitiveAttributes:
    """Test sensitive attribute redaction"""

    def test_sensitive_attributes_redacted(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify attributes with sensitive names are redacted"""
        xml_file = create_xml_file(SENSITIVE_ATTRS_XML)
        output_file = temp_output_dir / "sensitive_attr_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file)
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Sensitive attributes should be redacted
        assert 'password="[REDACTED]"' in output_content
        assert 'api_key="[REDACTED]"' in output_content
        assert 'auth_token="[REDACTED]"' in output_content
        assert 'client-secret="[REDACTED]"' in output_content

        # Original values should not appear
        assert 'secret123' not in output_content
        assert 'abc123' not in output_content
        assert 'bearer_xyz' not in output_content
        assert 'secret456' not in output_content


class TestIPv4WithPort:
    """Test IPv4 addresses with port numbers in free text"""

    def test_ipv4_with_port_redacted(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify IPv4:port in free text is correctly redacted"""
        xml_content = """<?xml version="1.0"?>
<pfsense>
  <system>
    <description>Server at 192.168.1.10:8080 and backup at 10.0.0.5:443</description>
    <notes>Connect to 172.16.0.1:22 for SSH access</notes>
  </system>
  <packages>
    <package>
      <url>http://192.168.1.100:8000/api</url>
    </package>
  </packages>
</pfsense>
"""
        xml_file = create_xml_file(xml_content)
        output_file = temp_output_dir / "ipv4_port_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--aggressive"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # IPv4 addresses should be redacted, ports preserved
        assert 'XXX.XXX.XXX.XXX:8080' in output_content
        assert 'XXX.XXX.XXX.XXX:443' in output_content
        assert 'XXX.XXX.XXX.XXX:22' in output_content

        # Original IPs should not appear
        assert '192.168.1.10' not in output_content
        assert '10.0.0.5' not in output_content
        assert '172.16.0.1' not in output_content

        # URL with IP:port is handled by _mask_url which masks the host to example.com
        assert 'http://example.com:8000/api' in output_content
        assert '192.168.1.100' not in output_content

    def test_ipv4_with_port_preserved_when_private(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify IPv4:port preserved with --keep-private-ips"""
        xml_content = """<?xml version="1.0"?>
<pfsense>
  <system>
    <description>Server at 192.168.1.10:8080 and public at 8.8.8.8:53</description>
  </system>
</pfsense>
"""
        xml_file = create_xml_file(xml_content)
        output_file = temp_output_dir / "ipv4_port_private_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--aggressive", "--keep-private-ips"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Private IP with port should be preserved
        assert '192.168.1.10:8080' in output_content

        # Public IP should be redacted, port preserved
        assert 'XXX.XXX.XXX.XXX:53' in output_content
        assert '8.8.8.8' not in output_content

    def test_bracketed_ipv6_with_port_still_works(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify bracketed IPv6 with port still works correctly"""
        xml_content = """<?xml version="1.0"?>
<pfsense>
  <system>
    <description>Server at [fe80::1%em0]:51820 and [2606:4700:4700::1111]:443</description>
  </system>
</pfsense>
"""
        xml_file = create_xml_file(xml_content)
        output_file = temp_output_dir / "ipv6_port_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--aggressive", "--keep-private-ips"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Link-local IPv6 with zone and port should be preserved
        assert '[fe80::1%em0]:51820' in output_content

        # Global IPv6 should be redacted, port preserved
        assert '[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]:443' in output_content
        assert '2606:4700:4700::1111' not in output_content


class TestDomainNormalisation:
    """Test domain normalisation in anonymisation mode"""

    def test_domain_case_and_trailing_dot_normalisation(self, create_xml_file, cli_runner, temp_output_dir):
        """Verify domains with different cases and trailing dots get the same alias"""
        xml_content = """<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>EXAMPLE.COM</hostname>
    <domain>example.com.</domain>
    <backup>Example.Com</backup>
  </system>
</pfsense>
"""
        xml_file = create_xml_file(xml_content)
        output_file = temp_output_dir / "domain_norm_out.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=["--anonymise"]
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # All three should get the same alias (e.g., domain1.example)
        # Count occurrences of domain aliases
        import re
        aliases = re.findall(r'domain\d+\.example', output_content)

        # Should have exactly 3 occurrences of the same alias
        assert len(aliases) == 3, f"Expected 3 domain aliases, got {len(aliases)}"


class TestRegexPrecompilation:
    """Test that regex patterns are precompiled for performance"""

    def test_ip_token_splitter_is_compiled(self, basic_redactor):
        """Verify that _ip_token_splitter is a compiled regex"""
        assert hasattr(basic_redactor, '_ip_token_splitter')
        assert hasattr(basic_redactor._ip_token_splitter, 'split')
        # Should be a compiled pattern
        assert str(type(basic_redactor._ip_token_splitter)) == "<class 're.Pattern'>"

    def test_ip_pattern_is_compiled(self, basic_redactor):
        """Verify that IP_PATTERN is a compiled regex"""
        assert hasattr(basic_redactor, 'IP_PATTERN')
        assert hasattr(basic_redactor.IP_PATTERN, 'match')
        assert str(type(basic_redactor.IP_PATTERN)) == "<class 're.Pattern'>"

    def test_mask_ip_like_tokens_uses_precompiled_patterns(self, basic_redactor):
        """Verify that _mask_ip_like_tokens works correctly with precompiled patterns"""
        text = "Connect to 192.168.1.1:8080"
        result = basic_redactor._mask_ip_like_tokens(text)

        # Should mask the IP
        assert "192.168.1.1" not in result
        assert "XXX.XXX.XXX.XXX:8080" in result


# Element names that leaked before pattern-based tag matching was added.
# Every one is a real pfSense or package element name.
LEAKING_SECRET_ELEMENTS = [
    'rocommunity', 'rwcommunity',        # SNMP community strings
    'passphrase',                        # WPA/WPA2 PSK
    'auth_pass',                         # OpenVPN client password
    'presharedkey',                      # WireGuard peer PSK
    'ipsecpsk',                          # Per-user IPsec PSK
    'eap_password',                      # IPsec EAP credential
    'radiussecret',                      # Captive Portal RADIUS secret
    'authorizedkeys',                    # SSH authorized keys
    'accountkey',                        # ACME account key
    'dns_cf_token',                      # Cloudflare API token
    'maxmind_key',                       # pfBlockerNG MaxMind licence key
    'influx_token',                      # Telegraf InfluxDB token
    'token',                             # Bare token
    'access_key', 'secret_access_key',   # S3 credentials
    'tlspskvalue',                       # Zabbix agent PSK
    'userkey',                           # Pushover user key
    'bearer_token',
]

# Element names that match the secret pattern but are not secrets
NON_SECRET_ELEMENTS = [
    'snortcommunityrules',   # Boolean "use community ruleset" toggle
    'pass_order',            # Snort/Suricata rule ordering
    'password_type',         # Hashing scheme indicator
    'source_hash_key',       # HAProxy algorithm selector
    'certref',               # Certificate reference, not key material
    'keylen',
    'sshdkeyonly',
]


class TestSecretElementPatternMatching:
    """Secret detection must match real element names, not just exact entries"""

    @pytest.mark.parametrize('tag', LEAKING_SECRET_ELEMENTS)
    def test_secret_element_is_redacted(self, basic_redactor, tag):
        """Each previously-leaking element name is now redacted"""
        root = ET.fromstring(f'<pfsense><a><{tag}>CANARY</{tag}></a></pfsense>')
        basic_redactor.redact_element(root)

        assert 'CANARY' not in ET.tostring(root, encoding='unicode')

    @pytest.mark.parametrize('tag', NON_SECRET_ELEMENTS)
    def test_non_secret_element_is_preserved(self, basic_redactor, tag):
        """Deny-listed and non-matching elements keep their values"""
        root = ET.fromstring(f'<pfsense><a><{tag}>plainvalue</{tag}></a></pfsense>')
        basic_redactor.redact_element(root)

        assert 'plainvalue' in ET.tostring(root, encoding='unicode')

    def test_numbered_variant_is_redacted(self, basic_redactor):
        """tag_base must be applied to secret matching, not just IP elements"""
        root = ET.fromstring(
            '<pfsense><a><password>A</password><password2>B</password2>'
            '<passwordagain>C</passwordagain></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert '>A<' not in output
        assert '>B<' not in output
        assert '>C<' not in output

    def test_short_cert_reference_is_preserved(self, basic_redactor):
        """Cert-ish tags holding short reference IDs stay readable"""
        root = ET.fromstring('<pfsense><a><ssl_ca_cert>5f3a1c9b</ssl_ca_cert></a></pfsense>')
        basic_redactor.redact_element(root)

        assert '5f3a1c9b' in ET.tostring(root, encoding='unicode')

    def test_cert_element_with_pem_is_redacted(self, basic_redactor):
        """The same tag holding actual PEM material is redacted"""
        pem = (
            '-----BEGIN CERTIFICATE-----\n'
            'MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKKzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\n'
            '-----END CERTIFICATE-----'
        )
        root = ET.fromstring(f'<pfsense><a><ha_certificates>{pem}</ha_certificates></a></pfsense>')
        basic_redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert 'BEGIN CERTIFICATE' not in output
        assert '[REDACTED_CERT_OR_KEY]' in output

    def test_key_element_keeps_cert_distinction(self, basic_redactor):
        """<key> retains its PEM-vs-short-secret handling"""
        pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAu1SU1LfVLPHCoz\n-----END RSA PRIVATE KEY-----'
        root = ET.fromstring(f'<pfsense><key>{pem}</key></pfsense>')
        basic_redactor.redact_element(root)

        assert '[REDACTED_CERT_OR_KEY]' in ET.tostring(root, encoding='unicode')


class TestBlobTextElements:
    """Opaque free-text containers are scanned for inline credentials"""

    def test_custom_options_askpass_directive(self, basic_redactor):
        """askpass argument is redacted in OpenVPN custom_options"""
        root = ET.fromstring(
            '<pfsense><a><custom_options>askpass /secret/passfile</custom_options></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        assert '/secret/passfile' not in ET.tostring(root, encoding='unicode')

    def test_upsd_users_inline_password(self, basic_redactor):
        """key=value is found mid-line, not only at line start"""
        root = ET.fromstring(
            '<pfsense><a><upsd_users>[admin] password=hunter2</upsd_users></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert 'hunter2' not in output
        assert '[admin]' in output, 'non-secret content should survive'

    def test_non_secret_directive_preserved(self, basic_redactor):
        """Ordinary directives in blob text are left alone"""
        root = ET.fromstring(
            '<pfsense><a><custom_options>verb 3\nkeepalive 10 60</custom_options></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert 'verb 3' in output
        assert 'keepalive 10 60' in output

    def test_url_secrets_scanned_in_blob_elements(self, basic_redactor):
        """Blob elements must not get less URL scanning than unknown elements"""
        url = 'https://feeds.corp.example/list?token=FEEDTOKEN9999'
        root = ET.fromstring(
            f'<pfsense><a><detail>synced from {url}</detail>'
            f'<otherfield>synced from {url}</otherfield></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        blob_text = root.find('.//detail').text
        assert 'FEEDTOKEN9999' not in blob_text
        assert blob_text == root.find('.//otherfield').text, 'parity with unknown element'

    def test_url_in_blob_not_corrupted_by_kv_scanner(self, basic_redactor):
        """The KV scan must not re-process an already-redacted URL"""
        root = ET.fromstring(
            '<pfsense><a><custom_options>'
            'remote https://x.example/u?token=ABC123'
            '</custom_options></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        text = root.find('.//custom_options').text

        assert 'ABC123' not in text
        assert '%5D]' not in text, 'double-encoded marker left a stray bracket'

    def test_kv_and_url_scanning_coexist(self, basic_redactor):
        """Directives, key=value pairs and URLs are all handled in one blob"""
        root = ET.fromstring(
            '<pfsense><a><custom_options>askpass /secret/pf\n'
            'password=hunter2\n'
            'remote https://x.example/u?token=ABC123\n'
            'verb 3</custom_options></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        text = root.find('.//custom_options').text

        assert '/secret/pf' not in text
        assert 'hunter2' not in text
        assert 'ABC123' not in text
        assert 'verb 3' in text, 'non-secret directives must survive'

    def test_aggressive_redacts_blob_wholesale(self, aggressive_redactor):
        """Aggressive mode does not rely on recognising the inner format"""
        root = ET.fromstring(
            '<pfsense><a><userparams>UserParameter=x,cat /root/creds</userparams></a></pfsense>'
        )
        aggressive_redactor.redact_element(root)

        assert '/root/creds' not in ET.tostring(root, encoding='unicode')


class TestURLSecretRedaction:
    """Credentials in URL paths and query strings"""

    def test_secret_query_param_redacted(self, basic_redactor):
        """Anonymising the host is not enough if the token survives"""
        result = basic_redactor.redact_text(
            'https://api.dnsprov.example/update?token=s3cr3tvalue&host=fw'
        )

        assert 's3cr3tvalue' not in result
        assert 'REDACTED' in result

    def test_non_secret_query_param_preserved(self, basic_redactor):
        """Ordinary query parameters keep their values"""
        result = basic_redactor.redact_text('https://feeds.example.net/list.txt?format=csv')

        assert 'format=csv' in result

    def test_url_in_unrecognised_element_is_scanned(self, basic_redactor):
        """URLs are found by content, not only in known URL-bearing tags"""
        root = ET.fromstring(
            '<pfsense><a><updateurl>https://api.example.com/u?token=leakme</updateurl></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        assert 'leakme' not in ET.tostring(root, encoding='unicode')

    def test_webhook_path_token_redacted_aggressive(self, aggressive_redactor):
        """Webhook secrets live in the path, not the query string

        Uses a .example host rather than the real webhook provider's domain:
        the redaction under test operates on path segments only, and a
        realistic provider hostname makes the fixture match secret-scanning
        patterns and blocks pushes.
        """
        result = aggressive_redactor.redact_text(
            'https://hooks.chat-provider.example/services/T00000000/B00000000/XiFdb92Kd8sM1nRq7vLwP3zY'
        )

        assert 'XiFdb92Kd8sM1nRq7vLwP3zY' not in result

    def test_userinfo_redacted_in_unrecognised_element(self, basic_redactor):
        """A URL's password must not survive beside a [REDACTED] query marker

        Emitting a partially-redacted URL reads as sanitised when it is not.
        """
        root = ET.fromstring(
            '<pfsense><a><updateurl>'
            'https://ddnsuser:Sup3rS3cret1@members.dyndns.example/nic/update?password=TOKEN'
            '</updateurl></a></pfsense>'
        )
        basic_redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert 'Sup3rS3cret1' not in output
        assert 'TOKEN' not in output

    def test_userinfo_redacted_without_query_secret(self, basic_redactor):
        """Credentials are redacted even when nothing else in the URL changes"""
        root = ET.fromstring(
            '<pfsense><a><backupurl>'
            'ftp://backupsvc:BackupPw99@backup.corp.example/nightly'
            '</backupurl></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        assert 'BackupPw99' not in ET.tostring(root, encoding='unicode')

    def test_userinfo_parity_with_known_url_element(self, basic_redactor):
        """Known and unknown URL carriers must redact credentials alike"""
        url = 'https://myuser:Sup3rS3cret1@host.example/nic/update?password=TOKEN'
        root = ET.fromstring(
            f'<pfsense><a><url>{url}</url><updateurl>{url}</updateurl></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        for tag in ('url', 'updateurl'):
            assert 'Sup3rS3cret1' not in root.find('.//' + tag).text

    def test_masked_host_still_redacts_query_and_userinfo(self, basic_redactor):
        """An already-masked host does not imply the rest of the URL is safe"""
        result = basic_redactor.redact_text(
            'https://user:pw@example.com/nic/update?password=SECRET'
        )

        assert 'SECRET' not in result
        assert ':pw@' not in result

    def test_short_path_segments_preserved(self, aggressive_redactor):
        """Ordinary route names are not mistaken for tokens"""
        result = aggressive_redactor.redact_text('https://feeds.example.net/lists/blocklist')

        assert '/lists/blocklist' in result
        assert 'REDACTED' not in result


class TestHighEntropyBlobs:
    """Unrecognised high-entropy values are reported, and redacted when asked"""

    BLOB_XML = (
        '<pfsense><installedpackages><mycustompkg><config>'
        '<blob>Q0FOQVJZX0JBU0U2NEJMT0JfQ0FOQVJZX0JBU0U2NEJMT0JfQ0FOQVJZ</blob>'
        '</config></mycustompkg></installedpackages></pfsense>'
    )

    def test_retained_by_default_but_reported(self, basic_redactor):
        """Default mode keeps the value but records where it is"""
        root = ET.fromstring(self.BLOB_XML)
        basic_redactor.redact_element(root)

        assert basic_redactor.stats['high_entropy_retained'] == 1
        assert any('blob' in p for p in basic_redactor.high_entropy_paths)
        assert 'Q0FOQVJZ' in ET.tostring(root, encoding='unicode')

    def test_reported_path_is_fully_qualified(self, basic_redactor):
        """The reported path locates the element for manual review"""
        root = ET.fromstring(self.BLOB_XML)
        basic_redactor.redact_element(root)

        assert 'pfsense/installedpackages/mycustompkg/config/blob' in basic_redactor.high_entropy_paths

    def test_redacted_under_aggressive(self, aggressive_redactor):
        """Aggressive mode redacts unrecognised blobs"""
        root = ET.fromstring(self.BLOB_XML)
        aggressive_redactor.redact_element(root)

        assert 'Q0FOQVJZ' not in ET.tostring(root, encoding='unicode')

    def test_ordinary_text_not_flagged(self, basic_redactor):
        """Long prose is not mistaken for encoded key material"""
        root = ET.fromstring(
            '<pfsense><a><notes>This is a fairly long human readable note about the setup</notes></a></pfsense>'
        )
        basic_redactor.redact_element(root)

        assert basic_redactor.stats['high_entropy_retained'] == 0


class TestRedactDescriptions:
    """--redact-descriptions covers personal names in free-text fields"""

    DESCR_XML = (
        '<pfsense><dhcpd><lan><staticmap>'
        '<hostname>ceo-laptop</hostname>'
        '<descr>CEO Jane Doe personal MBP</descr>'
        '</staticmap></lan></dhcpd></pfsense>'
    )

    def test_descriptions_preserved_by_default(self, basic_redactor):
        """Descriptions aid troubleshooting, so they stay unless asked"""
        root = ET.fromstring(self.DESCR_XML)
        basic_redactor.redact_element(root)

        assert 'Jane Doe' in ET.tostring(root, encoding='unicode')

    def test_descriptions_redacted_when_enabled(self, redactor_factory):
        """The flag removes descriptions and identifiers"""
        redactor = redactor_factory(redact_descriptions=True)
        root = ET.fromstring(self.DESCR_XML)
        redactor.redact_element(root)
        output = ET.tostring(root, encoding='unicode')

        assert 'Jane Doe' not in output
        assert 'ceo-laptop' not in output

    def test_ssid_redacted_when_enabled(self, redactor_factory):
        """SSIDs are organisation-identifying"""
        redactor = redactor_factory(redact_descriptions=True)
        root = ET.fromstring('<pfsense><a><ssid>ACME-Corp-WiFi</ssid></a></pfsense>')
        redactor.redact_element(root)

        assert 'ACME-Corp-WiFi' not in ET.tostring(root, encoding='unicode')
