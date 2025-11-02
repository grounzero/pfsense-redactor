"""
Property-style checks for redaction behaviour

Lightweight tests that verify general properties hold across various inputs
"""
import pytest
import re
import random
import ipaddress


def generate_random_ips(count=10, include_private=True, include_public=True):
    """Generate random IP addresses for testing"""
    ips = []

    if include_private:
        # RFC1918
        for _ in range(count // 3):
            ips.append(f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}")
            ips.append(f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")
            ips.append(f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}")

    if include_public:
        # Public IPs (avoiding reserved ranges)
        for _ in range(count // 3):
            ips.append(f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")

    return ips


def test_keep_private_preserves_all_non_global(cli_runner, create_xml_file, tmp_path):
    """
    Property: With --keep-private-ips, all non-global IPs should be preserved
    and global IPs should be masked (unless in allow-list)
    """
    # Generate mix of private and public IPs
    private_ips = [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.1.1",  # Link-local
        "0.0.0.0",      # Unspecified
    ]

    # Public IPs (should be masked without allow-list)
    public_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
    ]

    # Build XML with these IPs
    xml_content = '<?xml version="1.0"?>\n<pfsense>\n'
    for i, ip in enumerate(private_ips + public_ips):
        xml_content += f'  <system><dnsserver{i}>{ip}</dnsserver{i}></system>\n'
    xml_content += '</pfsense>'

    xml_file = create_xml_file(xml_content)
    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--keep-private-ips"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # All private IPs should be preserved
    for ip in private_ips:
        assert ip in output_content, f"Private IP {ip} should be preserved"

    # Public IPs should be masked (no hard-coded whitelist)
    for ip in public_ips:
        assert ip not in output_content, f"Public IP {ip} should be masked"


def test_no_pem_markers_in_output(sample_files, cli_runner, temp_output_dir):
    """
    Property: No PEM markers should remain in output when present in input
    """
    pem_markers = [
        "BEGIN CERTIFICATE",
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN ENCRYPTED PRIVATE KEY",
        "BEGIN PUBLIC KEY",
        "BEGIN OPENVPN STATIC KEY",
        "BEGIN OPENSSH PRIVATE KEY",
    ]

    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_no_pem.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file)
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Check input for PEM markers
        input_content = sample_file.read_text()
        has_pem_in_input = any(marker in input_content for marker in pem_markers)

        if has_pem_in_input:
            # Verify no PEM markers in output
            for marker in pem_markers:
                assert marker not in output_content, (
                    f"PEM marker '{marker}' should not appear in output"
                )


def test_redaction_is_idempotent(cli_runner, create_xml_file, tmp_path):
    """
    Property: Running redaction twice should produce same result
    """
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <password>secret123</password>
    <dnsserver>8.8.8.8</dnsserver>
    <hostname>firewall.example.com</hostname>
  </system>
  <cert>
    <crt>-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKKzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
-----END CERTIFICATE-----</crt>
  </cert>
</pfsense>
""")

    # First redaction
    output1 = tmp_path / "output1.xml"
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output1)
    )
    assert exit_code == 0

    # Second redaction on first output
    output2 = tmp_path / "output2.xml"
    exit_code, stdout, stderr = cli_runner.run(
        str(output1),
        str(output2)
    )
    assert exit_code == 0

    # Outputs should be identical
    content1 = output1.read_text()
    content2 = output2.read_text()

    # Normalize whitespace for comparison
    lines1 = [line.rstrip() for line in content1.splitlines()]
    lines2 = [line.rstrip() for line in content2.splitlines()]

    assert lines1 == lines2, "Redaction should be idempotent"


def test_xml_structure_preserved(sample_files, cli_runner, temp_output_dir):
    """
    Property: XML structure (elements, hierarchy) should be preserved
    """
    import xml.etree.ElementTree as ET

    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_structure.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file)
        )

        assert exit_code == 0

        # Parse both files
        input_tree = ET.parse(sample_file)
        output_tree = ET.parse(output_file)

        input_root = input_tree.getroot()
        output_root = output_tree.getroot()

        # Compare structure (not content)
        def get_structure(element, path=""):
            """Get element structure as set of paths"""
            tag = element.tag.rsplit('}', 1)[-1]  # Remove namespace
            current_path = f"{path}/{tag}"
            paths = {current_path}
            for child in element:
                paths.update(get_structure(child, current_path))
            return paths

        input_structure = get_structure(input_root)
        output_structure = get_structure(output_root)

        # Structure should be identical
        assert input_structure == output_structure, (
            f"XML structure changed for {sample_file.name}"
        )


def test_no_original_secrets_in_output(sample_files, cli_runner, temp_output_dir):
    """
    Property: Common secret patterns should not appear in output
    """
    # Patterns that commonly appear in secrets (more specific to avoid false positives)
    secret_patterns = [
        r'[A-Za-z0-9+/]{60,}={0,2}',  # Base64 encoded data (60+ chars to avoid IDs)
        r'-----BEGIN [A-Z ]+-----',    # PEM markers
        r'\$2[aby]\$\d+\$[./A-Za-z0-9]{53}',  # bcrypt hashes
    ]

    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_no_secrets.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file)
        )

        assert exit_code == 0

        input_content = sample_file.read_text()
        output_content = output_file.read_text()

        # Find potential secrets in input
        input_secrets = set()
        for pattern in secret_patterns:
            matches = re.findall(pattern, input_content)
            input_secrets.update(matches)

        # Check they don't appear in output (except for very short ones that might be IDs)
        for secret in input_secrets:
            if len(secret) > 30:  # Only check substantial secrets
                assert secret not in output_content, (
                    f"Secret pattern '{secret[:20]}...' found in output"
                )


def test_ipv6_zone_identifiers_preserved(cli_runner, create_xml_file, tmp_path):
    """
    Property: IPv6 zone identifiers should be preserved in structure
    """
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <interfaces>
    <lan>
      <ipaddrv6>fe80::1%em0</ipaddrv6>
      <ipaddrv6>fe80::2%eth0</ipaddrv6>
    </lan>
  </interfaces>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--keep-private-ips"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # Zone identifiers should be preserved
    assert "%em0" in output_content
    assert "%eth0" in output_content

    # Link-local addresses should be preserved
    assert "fe80::1" in output_content
    assert "fe80::2" in output_content


def test_ipv6_with_port_preserved(cli_runner, create_xml_file, tmp_path):
    """
    Property: IPv6 addresses with ports [addr]:port should preserve structure
    """
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <wireguard>
    <peer>
      <endpoint>[fe80::1%em0]:51820</endpoint>
      <endpoint>[fc00::1]:51821</endpoint>
    </peer>
  </wireguard>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--keep-private-ips"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # Port numbers should be preserved
    assert ":51820" in output_content
    assert ":51821" in output_content

    # Bracket structure should be preserved
    assert "[" in output_content and "]:" in output_content


def test_anonymise_consistency_across_runs(cli_runner, create_xml_file, tmp_path):
    """
    Property: Anonymisation should be consistent within a single run
    """
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>93.184.216.34</dnsserver>
    <dnsserver2>93.184.216.34</dnsserver2>
    <dnsserver3>93.184.216.35</dnsserver3>
    <hostname>mail.example.com</hostname>
    <domain>mail.example.com</domain>
    <backup>mail.example.com</backup>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--anonymise"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # Find all IP aliases (more flexible pattern)
    ip_aliases = re.findall(r'IP_\d+', output_content)

    # Should have at least some IP anonymisation (using non-whitelisted IPs)
    assert len(ip_aliases) >= 1, "Should have at least one anonymised IP"

    # If we have multiple, check consistency
    if len(ip_aliases) >= 2:
        # Count occurrences of each alias
        from collections import Counter
        alias_counts = Counter(ip_aliases)
        # The most common alias should appear at least twice (93.184.216.34 appears twice)
        most_common_count = alias_counts.most_common(1)[0][1]
        assert most_common_count >= 2, "Same IP should get same alias"

    # Find all domain aliases
    domain_aliases = re.findall(r'domain\d+\.example', output_content)

    # Should have some domain anonymisation
    if len(domain_aliases) >= 3:
        from collections import Counter
        domain_counts = Counter(domain_aliases)
        # mail.example.com appears three times, should have same alias
        most_common_count = domain_counts.most_common(1)[0][1]
        assert most_common_count >= 3, "Same domain should get same alias"


def test_netmasks_always_preserved_regardless_of_mode(cli_runner, create_xml_file, tmp_path):
    """
    Property: Common netmasks should always be preserved
    """
    netmasks = [
        "255.255.255.0",
        "255.255.0.0",
        "255.0.0.0",
        "255.255.255.128",
        "255.255.255.192",
        "255.255.255.224",
        "255.255.255.240",
        "255.255.255.248",
        "255.255.255.252",
        "255.255.255.254",
        "255.255.255.255",
    ]

    xml_content = '<?xml version="1.0"?>\n<pfsense>\n'
    for i, mask in enumerate(netmasks):
        xml_content += f'  <interfaces><lan{i}><subnet>{mask}</subnet></lan{i}></interfaces>\n'
    xml_content += '</pfsense>'

    xml_file = create_xml_file(xml_content)

    # Test with different modes
    modes = [
        [],
        ["--keep-private-ips"],
        ["--anonymise"],
        ["--aggressive"],
    ]

    for mode_flags in modes:
        output_file = tmp_path / f"output_{'_'.join(mode_flags) or 'default'}.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=mode_flags
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # All netmasks should be preserved
        for mask in netmasks:
            assert mask in output_content, (
                f"Netmask {mask} should be preserved with flags {mode_flags}"
            )


def test_unspecified_addresses_always_preserved(cli_runner, create_xml_file, tmp_path):
    """
    Property: Unspecified addresses (0.0.0.0, ::) should always be preserved
    """
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <gateway>0.0.0.0</gateway>
    <gatewayv6>::</gatewayv6>
  </system>
</pfsense>
""")

    # Test with different modes
    modes = [
        [],
        ["--keep-private-ips"],
        ["--anonymise"],
    ]

    for mode_flags in modes:
        output_file = tmp_path / f"unspec_{'_'.join(mode_flags) or 'default'}.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(xml_file),
            str(output_file),
            flags=mode_flags
        )

        assert exit_code == 0
        output_content = output_file.read_text()

        # Unspecified addresses should be preserved
        assert "0.0.0.0" in output_content
        assert "::" in output_content or "<gatewayv6>::</gatewayv6>" in output_content
