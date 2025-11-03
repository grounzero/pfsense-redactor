"""
Allow-list feature tests

Tests for IP and domain allow-list functionality including:
- CIDR notation support
- Domain suffix matching
- Wildcard domain notation
- IDNA/punycode handling
- Case-insensitive matching
- Statistics accuracy with allow-lists
"""
import re


def test_cidr_allowlist_cli_flag(cli_runner, create_xml_file, tmp_path):
    """Test CIDR notation in --allowlist-ip CLI flag"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>203.0.113.10</dnsserver>
    <dnsserver2>203.0.113.20</dnsserver2>
    <gateway>198.51.100.1</gateway>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    # Allow entire 203.0.113.0/24 range
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--allowlist-ip", "203.0.113.0/24"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # IPs in CIDR range should be preserved
    assert "203.0.113.10" in output_content
    assert "203.0.113.20" in output_content

    # IPs outside range should be redacted
    assert "198.51.100.1" not in output_content
    assert "XXX.XXX.XXX.XXX" in output_content


def test_cidr_allowlist_file(cli_runner, create_xml_file, tmp_path):
    """Test CIDR notation in allowlist file"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>10.10.10.5</dnsserver>
    <dnsserver2>10.10.20.5</dnsserver2>
    <gateway>192.168.1.1</gateway>
  </system>
</pfsense>
""")

    # Create allowlist file with CIDR
    allowlist_file = tmp_path / "allowlist.txt"
    allowlist_file.write_text("""# Test CIDR allowlist
10.10.10.0/24
192.168.0.0/16
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--allowlist-file", str(allowlist_file)]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # IPs in CIDR ranges should be preserved
    assert "10.10.10.5" in output_content
    assert "192.168.1.1" in output_content

    # IPs outside ranges should be redacted
    assert "10.10.20.5" not in output_content


def test_multiple_cidr_ranges(cli_runner, create_xml_file, tmp_path):
    """Test multiple CIDR ranges work together"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>203.0.113.10</dnsserver>
    <gateway>198.51.100.5</gateway>
    <server>8.8.8.8</server>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=[
            "--allowlist-ip", "203.0.113.0/24",
            "--allowlist-ip", "198.51.100.0/24"
        ]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # Both CIDR ranges should be preserved
    assert "203.0.113.10" in output_content
    assert "198.51.100.5" in output_content

    # IP outside ranges should be redacted
    assert "8.8.8.8" not in output_content


def test_invalid_cidr_error(cli_runner, create_xml_file, tmp_path):
    """Test that invalid CIDR notation produces clear error"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system><hostname>test</hostname></system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    # Try invalid CIDR
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--allowlist-ip", "not-a-valid-cidr"],
        expect_success=False
    )

    assert exit_code != 0
    assert "Invalid IP or CIDR" in stderr or "error" in stderr.lower()


def test_domain_suffix_matching(cli_runner, create_xml_file, tmp_path):
    """Test domain suffix matching (example.org preserves sub.example.org)"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>db.corp.example.org</hostname>
    <domain>admin.example.org</domain>
    <dnsserver>mail.example.org</dnsserver>
    <host>other.domain.com</host>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    # Allow example.org (should preserve all subdomains)
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--allowlist-domain", "example.org"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # All example.org subdomains should be preserved
    assert "db.corp.example.org" in output_content
    assert "admin.example.org" in output_content
    assert "mail.example.org" in output_content

    # Other domains should be redacted
    assert "other.domain.com" not in output_content
    assert "example.com" in output_content  # Default redaction


def test_wildcard_domain_allowlist(cli_runner, create_xml_file, tmp_path):
    """Test wildcard domain notation (*.example.org)"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>web.pfsense.org</hostname>
    <domain>docs.pfsense.org</domain>
    <server>forum.pfsense.org</server>
  </system>
</pfsense>
""")

    # Create allowlist with wildcard
    allowlist_file = tmp_path / "allowlist.txt"
    allowlist_file.write_text("*.pfsense.org\n")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--allowlist-file", str(allowlist_file)]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # All pfsense.org subdomains should be preserved
    assert "web.pfsense.org" in output_content
    assert "docs.pfsense.org" in output_content
    assert "forum.pfsense.org" in output_content


def test_idna_domain_matching(cli_runner, create_xml_file, tmp_path):
    """Test IDNA/punycode domain matching"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>xn--bcher-kva.example</hostname>
    <domain>test.xn--bcher-kva.example</domain>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    # Allow using Unicode form (should match punycode)
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--allowlist-domain", "bücher.example"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # Punycode domains should be preserved when Unicode is allow-listed
    assert "xn--bcher-kva.example" in output_content
    assert "test.xn--bcher-kva.example" in output_content


def test_case_insensitive_domain_matching(cli_runner, create_xml_file, tmp_path):
    """Test domain matching is case-insensitive"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>TIME.NIST.GOV</hostname>
    <domain>Time.Nist.Gov</domain>
    <server>time.nist.gov</server>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    # Allow using lowercase
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--allowlist-domain", "nist.gov"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # All case variations should be preserved
    assert "TIME.NIST.GOV" in output_content
    assert "Time.Nist.Gov" in output_content
    assert "time.nist.gov" in output_content


def test_trailing_dot_normalisation(cli_runner, create_xml_file, tmp_path):
    """Test that trailing dots in domains are handled correctly"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>server.example.org.</hostname>
    <domain>example.org</domain>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    # Allow with trailing dot
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--allowlist-domain", "example.org."]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # Both forms should be preserved
    assert "server.example.org." in output_content or "server.example.org" in output_content
    assert "example.org" in output_content


def test_combined_cidr_and_suffix_matching(cli_runner, create_xml_file, tmp_path):
    """Test CIDR and domain suffix matching work together"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>203.0.113.10</dnsserver>
    <gateway>198.51.100.1</gateway>
    <hostname>db.example.org</hostname>
    <domain>other.domain.com</domain>
  </system>
</pfsense>
""")

    # Create allowlist with both CIDR and domains
    allowlist_file = tmp_path / "allowlist.txt"
    allowlist_file.write_text("""# Mixed allowlist
203.0.113.0/24
example.org
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--allowlist-file", str(allowlist_file)]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # CIDR-matched IP should be preserved
    assert "203.0.113.10" in output_content

    # Suffix-matched domain should be preserved
    assert "db.example.org" in output_content

    # Non-matched items should be redacted
    assert "198.51.100.1" not in output_content
    assert "other.domain.com" not in output_content


def test_statistics_accuracy_with_allowlist(cli_runner, create_xml_file):
    """Test that statistics only count actual redactions, not preserved items"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>8.8.8.8</dnsserver>
    <dnsserver2>1.1.1.1</dnsserver2>
    <gateway>198.51.100.1</gateway>
    <hostname>time.nist.gov</hostname>
    <domain>pool.ntp.org</domain>
    <server>other.example.com</server>
  </system>
</pfsense>
""")

    # Run with allowlist
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=[
            "--dry-run",
            "--allowlist-ip", "8.8.8.8",
            "--allowlist-ip", "1.1.1.1",
            "--allowlist-domain", "nist.gov",
            "--allowlist-domain", "ntp.org"
        ]
    )

    assert exit_code == 0

    # Extract statistics
    ip_match = re.search(r'IP addresses:\s*(\d+)', stdout)
    domain_match = re.search(r'Domain names:\s*(\d+)', stdout)

    if ip_match:
        ip_count = int(ip_match.group(1))
        # Only 198.51.100.1 should be counted (8.8.8.8 and 1.1.1.1 are allow-listed)
        assert ip_count == 1, f"Expected 1 IP redacted, got {ip_count}"

    if domain_match:
        domain_count = int(domain_match.group(1))
        # Only other.example.com should be counted (nist.gov and ntp.org subdomains are allow-listed)
        assert domain_count == 1, f"Expected 1 domain redacted, got {domain_count}"


def test_allowlist_preserves_in_urls(cli_runner, create_xml_file, tmp_path):
    """Test that allow-listed domains are preserved in URLs"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <url>https://time.nist.gov/path</url>
    <url>https://other.example.com/path</url>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--allowlist-domain", "nist.gov"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # Allow-listed domain in URL should be preserved
    assert "time.nist.gov" in output_content

    # Non-allow-listed domain should be redacted
    assert "other.example.com" not in output_content


class TestCIDRAllowlist:
    """Test CIDR network allowlist functionality at the unit level"""

    def test_ip_in_cidr_range_preserved(self, redactor_factory):
        """Verify that IPs in CIDR allowlist are preserved"""
        import ipaddress

        # Allow 10.0.0.0/8
        networks = [ipaddress.ip_network('10.0.0.0/8')]
        redactor = redactor_factory(allowlist_networks=networks)

        text = "Server at 10.23.45.6"
        result = redactor.redact_text(text)

        # IP should be preserved
        assert "10.23.45.6" in result

    def test_ip_outside_cidr_range_masked(self, redactor_factory):
        """Verify that IPs outside CIDR allowlist are masked"""
        import ipaddress

        # Allow 10.0.0.0/8
        networks = [ipaddress.ip_network('10.0.0.0/8')]
        redactor = redactor_factory(allowlist_networks=networks)

        text = "Server at 192.168.1.1"
        result = redactor.redact_text(text)

        # IP should be masked
        assert "192.168.1.1" not in result
        assert "XXX.XXX.XXX.XXX" in result
