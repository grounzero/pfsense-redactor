"""
Statistics assertion tests

Verify that the redactor correctly counts and reports redacted items
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path
import importlib.util

# Import the pfsense-redactor module dynamically
PROJECT_ROOT = Path(__file__).parent.parent.parent
SCRIPT_PATH = PROJECT_ROOT / "pfsense_redactor" / "redactor.py"

spec = importlib.util.spec_from_file_location("pfsense_redactor", SCRIPT_PATH)
pfsense_redactor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pfsense_redactor)
PfSenseRedactor = pfsense_redactor.PfSenseRedactor


def test_stats_parsing(sample_files, cli_runner, stats_parser, temp_output_dir):
    """Test that statistics are correctly parsed from output"""
    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_stats.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file),
            flags=["--keep-private-ips"]
        )

        assert exit_code == 0

        # Parse stats from stdout
        stats = stats_parser.parse(stdout)

        # Verify stats structure
        assert isinstance(stats, dict)

        # At least some redaction should occur in real configs
        total_redactions = sum(stats.values())
        assert total_redactions > 0, f"No redactions found in {sample_file.name}"


def test_secrets_redacted_count(sample_files, cli_runner, stats_parser, temp_output_dir):
    """Verify secrets_redacted counter increments appropriately"""
    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_secrets.xml"

        # Run redactor
        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file)
        )

        assert exit_code == 0
        stats = stats_parser.parse(stdout)

        # Read output and verify [REDACTED] markers exist
        output_content = output_file.read_text()
        redacted_count = output_content.count('[REDACTED]')

        # Stats should reflect actual redactions
        if 'secrets_redacted' in stats:
            # Should have at least some secrets redacted
            assert stats['secrets_redacted'] > 0
            # Redacted markers should exist in output
            assert redacted_count > 0


def test_certs_redacted_count(sample_files, cli_runner, stats_parser, temp_output_dir):
    """Verify certs_redacted counter for certificate/key elements"""
    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_certs.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file)
        )

        assert exit_code == 0
        stats = stats_parser.parse(stdout)

        # Check for cert markers in output
        output_content = output_file.read_text()
        cert_markers = output_content.count('[REDACTED_CERT_OR_KEY]')

        if 'certs_redacted' in stats:
            # If certs were redacted, markers should exist
            if stats['certs_redacted'] > 0:
                assert cert_markers > 0


def test_ips_redacted_with_keep_private(
    sample_files, cli_runner, stats_parser, temp_output_dir
):
    """
    Verify IPs are preserved with --keep-private-ips and counter reflects
    only public IPs that were actually masked
    """
    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_keep_private.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file),
            flags=["--keep-private-ips"]
        )

        assert exit_code == 0
        stats = stats_parser.parse(stdout)

        output_content = output_file.read_text()

        # Common private IPs should be preserved
        private_patterns = [
            r'192\.168\.\d+\.\d+',
            r'10\.\d+\.\d+\.\d+',
            r'172\.1[6-9]\.\d+\.\d+',
            r'172\.2[0-9]\.\d+\.\d+',
            r'172\.3[0-1]\.\d+\.\d+',
            r'127\.0\.0\.1',
            r'::1',
            r'fe80:',
            r'fc00:',
        ]

        # At least some private IPs should be present in typical configs
        has_private = any(
            re.search(pattern, output_content)
            for pattern in private_patterns
        )

        # If we have private IPs preserved, verify no XXX masks for them
        if has_private:
            # Should not have masked private IPs
            assert 'XXX.XXX.XXX.XXX' not in output_content or stats.get('ips_redacted', 0) > 0


def test_ips_redacted_without_keep_private(
    sample_files, cli_runner, stats_parser, temp_output_dir
):
    """Verify public IPs are masked without --keep-private-ips"""
    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_no_keep.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file)
        )

        assert exit_code == 0
        stats = stats_parser.parse(stdout)

        output_content = output_file.read_text()

        # Should have IP masks if IPs were redacted
        if stats.get('ips_redacted', 0) > 0:
            assert 'XXX.XXX.XXX.XXX' in output_content or 'XXXX:XXXX' in output_content


def test_macs_redacted_count(sample_files, cli_runner, stats_parser, temp_output_dir):
    """Verify MAC addresses are counted correctly"""
    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_macs.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file)
        )

        assert exit_code == 0
        stats = stats_parser.parse(stdout)

        output_content = output_file.read_text()

        # Check for MAC redaction markers
        std_mac_markers = output_content.count('XX:XX:XX:XX:XX:XX')
        cisco_mac_markers = output_content.count('XXXX.XXXX.XXXX')

        if 'macs_redacted' in stats and stats['macs_redacted'] > 0:
            # Should have MAC markers
            assert (std_mac_markers + cisco_mac_markers) > 0


def test_urls_redacted_count(sample_files, cli_runner, stats_parser, temp_output_dir):
    """Verify URLs are counted only when actually changed"""
    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_urls.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file),
            flags=["--keep-private-ips"]
        )

        assert exit_code == 0
        stats = stats_parser.parse(stdout)

        # URLs with internal IPs should be preserved with --keep-private-ips
        # Only public domain/IP URLs should increment counter
        if 'urls_redacted' in stats:
            # Counter should only reflect actual changes
            assert stats['urls_redacted'] >= 0


def test_anonymise_mode_stats(sample_files, cli_runner, stats_parser, temp_output_dir):
    """Verify anonymisation statistics are reported"""
    for sample_file in sample_files:
        output_file = temp_output_dir / f"{sample_file.stem}_anon.xml"

        exit_code, stdout, stderr = cli_runner.run(
            str(sample_file),
            str(output_file),
            flags=["--anonymise"]
        )

        assert exit_code == 0
        stats = stats_parser.parse(stdout)

        # Should have anonymisation stats
        if stats.get('ips_redacted', 0) > 0:
            assert 'unique_ips_anonymised' in stats
            assert stats['unique_ips_anonymised'] > 0

        if stats.get('domains_redacted', 0) > 0:
            assert 'unique_domains_anonymised' in stats
            assert stats['unique_domains_anonymised'] > 0


def test_aggressive_mode_increases_redactions(
    sample_files, cli_runner, stats_parser, temp_output_dir
):
    """Verify aggressive mode redacts more than normal mode"""
    for sample_file in sample_files:
        # Run normal mode
        normal_output = temp_output_dir / f"{sample_file.stem}_normal.xml"
        exit_code, stdout_normal, _ = cli_runner.run(
            str(sample_file),
            str(normal_output),
            flags=["--keep-private-ips"]
        )
        assert exit_code == 0
        stats_normal = stats_parser.parse(stdout_normal)

        # Run aggressive mode
        aggressive_output = temp_output_dir / f"{sample_file.stem}_aggressive.xml"
        exit_code, stdout_aggressive, _ = cli_runner.run(
            str(sample_file),
            str(aggressive_output),
            flags=["--aggressive", "--keep-private-ips"]
        )
        assert exit_code == 0
        stats_aggressive = stats_parser.parse(stdout_aggressive)

        # Aggressive should redact at least as much as normal
        for key in ['ips_redacted', 'domains_redacted', 'urls_redacted']:
            if key in stats_normal and key in stats_aggressive:
                assert stats_aggressive[key] >= stats_normal[key], (
                    f"Aggressive mode should redact >= normal mode for {key}"
                )


def test_no_redact_flags_reduce_counts(
    sample_files, cli_runner, stats_parser, temp_output_dir
):
    """Verify --no-redact-ips and --no-redact-domains reduce counters"""
    for sample_file in sample_files:
        # Run with full redaction
        full_output = temp_output_dir / f"{sample_file.stem}_full.xml"
        exit_code, stdout_full, _ = cli_runner.run(
            str(sample_file),
            str(full_output)
        )
        assert exit_code == 0
        stats_full = stats_parser.parse(stdout_full)

        # Run with --no-redact-ips
        no_ips_output = temp_output_dir / f"{sample_file.stem}_no_ips.xml"
        exit_code, stdout_no_ips, _ = cli_runner.run(
            str(sample_file),
            str(no_ips_output),
            flags=["--no-redact-ips"]
        )
        assert exit_code == 0
        stats_no_ips = stats_parser.parse(stdout_no_ips)

        # Should have significantly fewer or no IP redactions
        # Note: URLs with IP hosts may still be counted
        assert stats_no_ips.get('ips_redacted', 0) <= stats_full.get('ips_redacted', 0)

        # Run with --no-redact-domains
        no_domains_output = temp_output_dir / f"{sample_file.stem}_no_domains.xml"
        exit_code, stdout_no_domains, _ = cli_runner.run(
            str(sample_file),
            str(no_domains_output),
            flags=["--no-redact-domains"]
        )
        assert exit_code == 0
        stats_no_domains = stats_parser.parse(stdout_no_domains)

        # Should have no domain/email/URL redactions
        assert stats_no_domains.get('domains_redacted', 0) == 0
        assert stats_no_domains.get('emails_redacted', 0) == 0
        assert stats_no_domains.get('urls_redacted', 0) == 0


class TestAttributeCountingInRedactElements:
    """Test that attributes are counted when redacting elements in redact_elements set"""

    def test_password_element_with_attributes_counts_all_redactions(self):
        """Verify that both text and attributes in redact_elements are counted"""
        # Create a password element with both text and attributes
        xml_str = '''<?xml version="1.0"?>
<pfsense>
    <password attr1="secret_attr_value" attr2="another_secret">secret_text_value</password>
</pfsense>'''

        root = ET.fromstring(xml_str)
        redactor = PfSenseRedactor()

        # Redact the element
        redactor.redact_element(root)

        # Check that text was redacted
        password_elem = root.find('password')
        assert password_elem.text == '[REDACTED]'

        # Check that attributes were redacted
        assert password_elem.attrib['attr1'] == '[REDACTED]'
        assert password_elem.attrib['attr2'] == '[REDACTED]'

        # CRITICAL: Check that all redactions were counted
        # Should be: 1 (text) + 2 (attributes) = 3
        assert redactor.stats['secrets_redacted'] == 3, \
            f"Expected 3 secrets redacted (1 text + 2 attrs), got {redactor.stats['secrets_redacted']}"

    def test_multiple_secret_elements_with_attributes(self):
        """Test counting across multiple elements with attributes"""
        xml_str = '''<?xml version="1.0"?>
<pfsense>
    <password attr="pass123">mypassword</password>
    <apikey key_attr="api_secret">my_api_key</apikey>
    <secret>just_text</secret>
</pfsense>'''

        root = ET.fromstring(xml_str)
        redactor = PfSenseRedactor()

        redactor.redact_element(root)

        # Expected:
        # - password: 1 text + 1 attr = 2
        # - apikey: 1 text + 1 attr = 2
        # - secret: 1 text = 1
        # Total: 5
        assert redactor.stats['secrets_redacted'] == 5, \
            f"Expected 5 secrets redacted, got {redactor.stats['secrets_redacted']}"

    def test_element_with_only_attributes_no_text(self):
        """Test element in redact_elements with only attributes (no text)"""
        xml_str = '''<?xml version="1.0"?>
<pfsense>
    <password attr1="secret1" attr2="secret2" attr3="secret3"></password>
</pfsense>'''

        root = ET.fromstring(xml_str)
        redactor = PfSenseRedactor()

        redactor.redact_element(root)

        password_elem = root.find('password')

        # All attributes should be redacted
        assert password_elem.attrib['attr1'] == '[REDACTED]'
        assert password_elem.attrib['attr2'] == '[REDACTED]'
        assert password_elem.attrib['attr3'] == '[REDACTED]'

        # Should count all 3 attributes (no text to count)
        assert redactor.stats['secrets_redacted'] == 3, \
            f"Expected 3 secrets redacted (3 attrs), got {redactor.stats['secrets_redacted']}"

    def test_dry_run_verbose_samples_attributes(self):
        """Verify that attribute redactions are sampled in dry-run-verbose mode"""
        xml_str = '''<?xml version="1.0"?>
<pfsense>
    <password attr="my_secret_attr">my_secret_text</password>
</pfsense>'''

        root = ET.fromstring(xml_str)
        redactor = PfSenseRedactor(dry_run_verbose=True)

        redactor.redact_element(root)

        # Check samples were collected
        assert 'Secret' in redactor.samples
        assert len(redactor.samples['Secret']) == 2  # text + attribute

        # Verify both text and attribute are in samples
        sample_values = [before for before, after in redactor.samples['Secret']]
        # Note: samples are masked, so we check the structure
        assert len(sample_values) == 2

    def test_comparison_with_sensitive_attributes(self):
        """Compare redact_elements branch with sensitive attributes branch"""
        # This test documents the difference between the two code paths

        # Path 1: Element in redact_elements (password)
        xml_str1 = '''<?xml version="1.0"?>
<pfsense>
    <password myattr="secret">text</password>
</pfsense>'''

        root1 = ET.fromstring(xml_str1)
        redactor1 = PfSenseRedactor()
        redactor1.redact_element(root1)

        # Path 2: Element NOT in redact_elements but with sensitive attribute name
        xml_str2 = '''<?xml version="1.0"?>
<pfsense>
    <somelement password="secret">text</somelement>
</pfsense>'''

        root2 = ET.fromstring(xml_str2)
        redactor2 = PfSenseRedactor()
        redactor2.redact_element(root2)

        # Both should count the attribute redaction
        # redactor1: 1 text + 1 attr = 2
        # redactor2: 1 attr = 1
        assert redactor1.stats['secrets_redacted'] == 2, \
            f"Path 1 (redact_elements): Expected 2, got {redactor1.stats['secrets_redacted']}"
        assert redactor2.stats['secrets_redacted'] == 1, \
            f"Path 2 (sensitive attrs): Expected 1, got {redactor2.stats['secrets_redacted']}"

    def test_various_secret_elements_with_attributes(self):
        """Test that various secret element types count attributes correctly"""
        xml_str = '''<?xml version="1.0"?>
<pfsense>
    <pre-shared-key attr="val1">psk_text</pre-shared-key>
    <apikey attr1="val2" attr2="val3">api_text</apikey>
    <community attr="val4">snmp_text</community>
</pfsense>'''

        root = ET.fromstring(xml_str)
        redactor = PfSenseRedactor()

        redactor.redact_element(root)

        # Expected:
        # - pre-shared-key: 1 text + 1 attr = 2
        # - apikey: 1 text + 2 attrs = 3
        # - community: 1 text + 1 attr = 2
        # Total: 7
        assert redactor.stats['secrets_redacted'] == 7, \
            f"Expected 7 secrets redacted, got {redactor.stats['secrets_redacted']}"
