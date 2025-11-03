"""
CLI behaviour and safety tests

Test command-line interface behaviour, error handling, and safety features
"""
import subprocess


def test_missing_input_file(cli_runner, tmp_path):
    """Test error when input file doesn't exist"""
    non_existent = tmp_path / "does_not_exist.xml"
    output = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(non_existent),
        str(output),
        expect_success=False
    )

    assert exit_code != 0
    assert "not found" in stderr.lower() or "error" in stderr.lower()


def test_empty_input_file(cli_runner, tmp_path):
    """Test error when input file is empty"""
    empty_file = tmp_path / "empty.xml"
    empty_file.write_text("")
    output = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(empty_file),
        str(output),
        expect_success=False
    )

    assert exit_code != 0
    assert "empty" in stderr.lower() or "error" in stderr.lower()


def test_output_required_without_special_modes(script_path, create_xml_file, tmp_path):
    """Test that output file is auto-generated if not provided"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system><hostname>test</hostname></system>
</pfsense>
""")

    # Should succeed and auto-generate output filename
    result = subprocess.run(
        ["python3", script_path, str(xml_file)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    # Check that output was written to auto-generated filename
    expected_output = xml_file.parent / f"{xml_file.stem}-redacted{xml_file.suffix}"
    assert expected_output.exists(), f"Expected auto-generated output file: {expected_output}"

    # Clean up
    if expected_output.exists():
        expected_output.unlink()


def test_stdout_mode_writes_to_stdout(cli_runner, create_xml_file):
    """Test --stdout writes XML to stdout"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system><password>secret</password></system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run_to_stdout(str(xml_file))

    assert exit_code == 0
    assert stdout, "No stdout output"
    assert "<?xml" in stdout
    assert "<pfsense>" in stdout
    assert "[REDACTED]" in stdout


def test_stats_stderr_with_stdout(cli_runner, create_xml_file):
    """Test --stats-stderr prints stats to stderr when using --stdout"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system><password>secret</password></system>
</pfsense>
""")

    exit_code, stdout, stderr = cli_runner.run_to_stdout(
        str(xml_file)
    )

    assert exit_code == 0
    assert "<?xml" in stdout
    assert "Redaction summary:" in stderr
    assert "Passwords/keys/secrets:" in stderr


def test_inplace_modifies_original(cli_runner, create_xml_file, tmp_path):
    """Test --inplace overwrites input file"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system><password>secret123</password></system>
</pfsense>
""", filename="inplace_test.xml")

    original_content = xml_file.read_text()
    assert "secret123" in original_content

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        output_file=None,
        flags=["--inplace"]
    )

    assert exit_code == 0

    # File should be modified
    modified_content = xml_file.read_text()
    assert modified_content != original_content
    assert "[REDACTED]" in modified_content
    assert "secret123" not in modified_content


def test_force_overwrites_existing_output(cli_runner, create_xml_file, tmp_path):
    """Test --force allows overwriting existing output file"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system><password>secret</password></system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"
    output_file.write_text("existing content")

    # Without --force, should fail
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        expect_success=False
    )

    assert exit_code != 0
    assert "exists" in stderr.lower() or "force" in stderr.lower()

    # With --force, should succeed
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--force"]
    )

    assert exit_code == 0
    assert output_file.exists()
    new_content = output_file.read_text()
    assert "[REDACTED]" in new_content


def test_dry_run_no_output(cli_runner, create_xml_file, tmp_path):
    """Test --dry-run doesn't create output file"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system><password>secret</password></system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--dry-run"]
    )

    assert exit_code == 0
    assert not output_file.exists(), "Output file should not be created in dry-run"
    assert "Dry run" in stdout or "dry run" in stdout.lower()
    assert "Redaction summary:" in stdout


def test_fail_on_warn_with_wrong_root(cli_runner, create_xml_file, tmp_path):
    """Test --fail-on-warn exits non-zero when root tag is not pfsense"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<config>
  <system><password>secret</password></system>
</config>
""")

    output_file = tmp_path / "output.xml"

    # Without --fail-on-warn, should succeed with warning
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file)
    )

    assert exit_code == 0
    assert "Warning" in stderr or "warning" in stderr.lower()

    # With --fail-on-warn, should fail
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--fail-on-warn", "--force"],
        expect_success=False
    )

    assert exit_code != 0


def test_fail_on_warn_accepts_namespaced_root(cli_runner, create_xml_file, tmp_path):
    """Test --fail-on-warn accepts namespaced pfsense root"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<ns:pfsense xmlns:ns="http://example.com/pfsense">
  <ns:system><ns:password>secret</ns:password></ns:system>
</ns:pfsense>
""")

    output_file = tmp_path / "output.xml"

    # Should succeed even with --fail-on-warn
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--fail-on-warn"]
    )

    assert exit_code == 0


def test_invalid_xml_fails_gracefully(cli_runner, create_xml_file, tmp_path):
    """Test invalid XML produces clear error"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <unclosed>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        expect_success=False
    )

    assert exit_code != 0
    assert "error" in stderr.lower() or "parse" in stderr.lower()


def test_no_redact_ips_flag(cli_runner, create_xml_file, tmp_path):
    """Test --no-redact-ips preserves all IPs"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>8.8.8.8</dnsserver>
    <gateway>192.168.1.1</gateway>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--no-redact-ips"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # Both public and private IPs should be preserved
    assert "8.8.8.8" in output_content
    assert "192.168.1.1" in output_content
    assert "XXX.XXX.XXX.XXX" not in output_content


def test_no_redact_domains_flag(cli_runner, create_xml_file, tmp_path):
    """Test --no-redact-domains preserves domains"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>firewall.example.com</hostname>
    <domain>example.org</domain>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--no-redact-domains"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    assert "<hostname>firewall.example.com</hostname>" in output_content
    assert "<domain>example.org</domain>" in output_content


def test_anonymise_implies_keep_private(cli_runner, create_xml_file, tmp_path):
    """Test --anonymise implies --keep-private-ips"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>93.184.216.34</dnsserver>
    <gateway>192.168.1.1</gateway>
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

    # Private IPs should be preserved
    assert "192.168.1.1" in output_content

    # Non-whitelisted public IPs should be anonymised (IP_N format)
    assert "IP_" in output_content
    assert "93.184.216.34" not in output_content

    # Should have anonymisation stats
    assert "Unique IPs anonymised:" in stdout


def test_anonymise_consistent_aliases(cli_runner, create_xml_file, tmp_path):
    """Test --anonymise produces consistent aliases"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>93.184.216.34</dnsserver>
    <dnsserver2>93.184.216.34</dnsserver2>
    <hostname>mail.example.com</hostname>
    <domain>mail.example.com</domain>
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

    # Same IP should get same alias
    import re
    ip_aliases = re.findall(r'IP_\d+', output_content)
    # 93.184.216.34 appears twice, should have same alias
    assert len(ip_aliases) >= 2
    assert ip_aliases[0] == ip_aliases[1]

    # Same domain should get same alias
    domain_aliases = re.findall(r'domain\d+\.example', output_content)
    if len(domain_aliases) >= 2:
        # Count occurrences of each alias
        from collections import Counter
        alias_counts = Counter(domain_aliases)
        # mail.example.com appears twice, should have same alias
        most_common_count = alias_counts.most_common(1)[0][1]
        assert most_common_count >= 2, "Same domain should get same alias"
    else:
        # At least some anonymisation should occur
        assert len(domain_aliases) >= 1 or 'IP_' in output_content


def test_aggressive_flag_increases_coverage(cli_runner, create_xml_file, tmp_path):
    """Test --aggressive redacts more broadly"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <description>Server at 8.8.8.8 with domain example.com</description>
  </system>
</pfsense>
""")

    # Without aggressive
    output_normal = tmp_path / "normal.xml"
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_normal)
    )
    assert exit_code == 0
    normal_content = output_normal.read_text()

    # With aggressive
    output_aggressive = tmp_path / "aggressive.xml"
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_aggressive),
        flags=["--aggressive"]
    )
    assert exit_code == 0
    aggressive_content = output_aggressive.read_text()

    # Aggressive should redact more (check counts or presence)
    normal_domain_count = normal_content.count("example.com")
    aggressive_domain_count = aggressive_content.count("example.com")

    # Aggressive should have fewer or equal occurrences
    assert aggressive_domain_count <= normal_domain_count


def test_combined_flags(cli_runner, create_xml_file, tmp_path):
    """Test multiple flags work together correctly"""
    xml_file = create_xml_file("""<?xml version="1.0"?>
<pfsense>
  <system>
    <password>secret</password>
    <dnsserver>93.184.216.34</dnsserver>
    <gateway>192.168.1.1</gateway>
    <hostname>firewall.example.com</hostname>
  </system>
</pfsense>
""")

    output_file = tmp_path / "output.xml"

    # Combine --keep-private-ips, --no-redact-domains, --aggressive
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file),
        flags=["--keep-private-ips", "--no-redact-domains", "--aggressive"]
    )

    assert exit_code == 0
    output_content = output_file.read_text()

    # Secrets still redacted
    assert "[REDACTED]" in output_content
    assert "secret" not in output_content

    # Private IPs preserved
    assert "192.168.1.1" in output_content

    # Non-whitelisted public IPs redacted
    assert "93.184.216.34" not in output_content

    assert "<hostname>firewall.example.com</hostname>" in output_content
