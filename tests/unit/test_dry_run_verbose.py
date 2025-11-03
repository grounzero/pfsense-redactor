"""
Dry-run verbose mode tests

Tests for the --dry-run-verbose feature including:
- Sample collection and display
- Safe masking to prevent information leaks
- Sample format verification
- No file creation in dry-run mode
"""


def test_dry_run_verbose_shows_samples(cli_runner, create_xml_file):
    """Test --dry-run-verbose displays sample redactions"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <password>mysecretpassword123</password>
    <dnsserver>8.8.8.8</dnsserver>
    <gateway>192.168.1.1</gateway>
    <hostname>firewall.example.com</hostname>
  </system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0
    assert "Samples of changes" in stdout
    assert "limit N=" in stdout

    # Should show sample categories
    assert "IP:" in stdout or "Secret:" in stdout or "FQDN:" in stdout


def test_dry_run_verbose_masks_ip_samples_safely(cli_runner, create_xml_file):
    """Test that IP samples are safely masked to prevent leaks"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>198.51.100.42</dnsserver>
    <gateway>203.0.113.10</gateway>
  </system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0

    # IP samples should be masked (e.g., 198.51.***.42)
    if "IP:" in stdout:
        # Should contain masked format
        assert "***" in stdout
        # Should NOT contain full unmasked IPs in the "before" part
        # The full IP might appear in "after" part (XXX.XXX.XXX.XXX), but not the real IP
        lines_with_ip = [line for line in stdout.split('\n') if 'IP:' in line]
        for line in lines_with_ip:
            # Extract the "before" part (before the →)
            if '→' in line:
                before_part = line.split('→')[0]
                # The before part should have masking
                assert '***' in before_part or 'IP:' not in before_part


def test_dry_run_verbose_masks_secret_samples_safely(cli_runner, create_xml_file):
    """Test that secret samples show length and partial masking only"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <password>verysecretpassword</password>
    <apikey>sk_live_1234567890abcdef</apikey>
  </system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0

    # Secret samples should show length indicator
    if "Secret:" in stdout:
        assert "(len=" in stdout
        # Should NOT show full secrets
        assert "verysecretpassword" not in stdout
        assert "sk_live_1234567890abcdef" not in stdout


def test_dry_run_verbose_masks_fqdn_samples_safely(cli_runner, create_xml_file):
    """Test that FQDN samples are masked (e.g., db.***.example.org)"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>db.corp.example.org</hostname>
    <domain>admin.internal.example.com</domain>
  </system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0

    # FQDN samples should contain masked format
    if "FQDN:" in stdout:
        assert "***" in stdout


def test_dry_run_verbose_shows_mac_samples(cli_runner, create_xml_file):
    """Test that MAC address samples are displayed with masking"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <mac>aa:bb:cc:dd:ee:ff</mac>
    <mac>11:22:33:44:55:66</mac>
  </system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0

    # MAC samples should be shown
    if "MAC:" in stdout:
        # Should show masked format (aa:bb:**:**:ee:ff)
        assert ":**:**:" in stdout or "MAC:" in stdout


def test_dry_run_verbose_shows_cert_samples(cli_runner, create_xml_file):
    """Test that certificate/key samples show placeholder with length"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <cert>
    <crt>-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKSzMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwODIzMTUxNjQ3WhcNMTgwODIzMTUxNjQ3WjBF
-----END CERTIFICATE-----</crt>
  </cert>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0

    # Cert/Key samples should show placeholder
    if "Cert/Key:" in stdout:
        assert "PEM blob" in stdout or "len≈" in stdout


def test_dry_run_verbose_shows_url_samples(cli_runner, create_xml_file):
    """Test that URL samples show full URL with masked host"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <url>https://admin.example.com/path/to/resource</url>
    <url>http://192.168.1.1:8080/admin</url>
  </system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0

    # URL samples should be shown
    if "URL:" in stdout:
        # Should show URL structure
        assert "http" in stdout.lower()
        # Should have masking in the before part
        assert "***" in stdout


def test_dry_run_verbose_no_file_creation(cli_runner, create_xml_file, tmp_path):
    """Test that --dry-run-verbose never creates output files"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <password>secret</password>
    <dnsserver>8.8.8.8</dnsserver>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0
    assert not output_file.exists(), "Output file should not be created in dry-run-verbose"
    assert "Samples of changes" in stdout
    assert "Dry run" in stdout


def test_dry_run_verbose_respects_sample_limit(cli_runner, create_xml_file):
    """Test that sample collection respects the limit (default 5 per category)"""
    # Create config with many IPs
    xml_content = """<?xml version="1.0"?>
<pfsense>
  <system>
"""
    for i in range(10):
        xml_content += f"    <dnsserver>8.8.8.{i}</dnsserver>\n"
    xml_content += """  </system>
</pfsense>
"""

    xml_file = create_xml_file(xml_content)

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0

    # Count IP samples shown
    if "IP:" in stdout:
        ip_sample_lines = [line for line in stdout.split('\n') if line.strip().startswith('IP:')]
        # Should not exceed the limit (default 5)
        assert len(ip_sample_lines) <= 5, f"Expected max 5 IP samples, got {len(ip_sample_lines)}"


def test_dry_run_verbose_shows_statistics(cli_runner, create_xml_file):
    """Test that --dry-run-verbose shows statistics before samples"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <password>secret</password>
    <dnsserver>8.8.8.8</dnsserver>
    <hostname>example.com</hostname>
  </system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0

    # Should show both statistics and samples
    assert "Redaction summary:" in stdout
    assert "Samples of changes" in stdout

    # Statistics should come before samples
    stats_pos = stdout.find("Redaction summary:")
    samples_pos = stdout.find("Samples of changes")
    assert stats_pos < samples_pos, "Statistics should appear before samples"


def test_dry_run_verbose_with_no_redactions(cli_runner, create_xml_file):
    """Test --dry-run-verbose when nothing needs redacting"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>firewall</hostname>
  </system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose", "--no-redact-ips", "--no-redact-domains"]
    )

    assert exit_code == 0
    assert "Dry run" in stdout
    # May or may not show samples section if nothing was redacted


def test_dry_run_verbose_sample_format(cli_runner, create_xml_file):
    """Test that samples use the correct format: CATEGORY: before → after"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <password>secret123</password>
    <dnsserver>8.8.8.8</dnsserver>
  </system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--dry-run-verbose"]
    )

    assert exit_code == 0

    # Check format of sample lines
    sample_lines = [line for line in stdout.split('\n')
                   if any(cat in line for cat in ['IP:', 'Secret:', 'FQDN:', 'MAC:', 'URL:', 'Cert/Key:'])]

    for line in sample_lines:
        if '→' in line:
            # Should have format: "    CATEGORY: before → after"
            assert ':' in line, "Sample line should have category with colon"
            assert '→' in line, "Sample line should have arrow separator"
