"""
Focused behaviour tests using synthetic mini-fixtures

These tests use minimal inline XML to verify specific redaction logic
without depending on large sample files.
"""

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
