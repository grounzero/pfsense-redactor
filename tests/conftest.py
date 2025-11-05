"""
Pytest configuration and shared fixtures for pfSense redactor tests
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest


# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
SCRIPT_PATH = PROJECT_ROOT / "pfsense_redactor" / "redactor.py"
TEST_CONFIGS_DIR = PROJECT_ROOT / "test-configs"
REFERENCE_DIR = PROJECT_ROOT / "tests" / "reference"


@pytest.fixture
def script_path():
    """Path to the pfsense_redactor module"""
    return str(SCRIPT_PATH)


@pytest.fixture
def test_configs_dir():
    """Path to test-configs directory"""
    return TEST_CONFIGS_DIR


@pytest.fixture
def reference_dir():
    """Path to reference outputs directory"""
    return REFERENCE_DIR


@pytest.fixture
def sample_files(test_configs_dir):
    """List of available sample config files"""
    if not test_configs_dir.exists():
        pytest.skip(f"Test configs directory not found: {test_configs_dir}")

    samples = list(test_configs_dir.glob("*.xml"))
    if not samples:
        pytest.skip(f"No XML files found in {test_configs_dir}")

    return samples


@pytest.fixture
def temp_output_dir(tmp_path):
    """Temporary directory for test outputs"""
    output_dir = tmp_path / "outputs"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def update_reference():
    """Check if reference files should be updated"""
    return os.environ.get("UPDATE_REFERENCE", "0") == "1"


class CLIRunner:
    """Helper class to run the pfsense-redactor CLI and capture results"""

    def __init__(self, script_path: str):
        self.script_path = script_path

    def run(
        self,
        input_file: str,
        output_file: str = None,
        flags: list[str] = None,
        expect_success: bool = True
    ) -> tuple[int, str, str]:
        """
        Run the CLI with specified arguments

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        cmd = ["python3", self.script_path, input_file]

        if output_file:
            cmd.append(output_file)

        if flags:
            cmd.extend(flags)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(PROJECT_ROOT),
            check=False
        )

        if expect_success and result.returncode != 0:
            raise AssertionError(
                f"Command failed with exit code {result.returncode}\n"
                f"Command: {' '.join(cmd)}\n"
                f"Stderr: {result.stderr}\n"
                f"Stdout: {result.stdout}"
            )

        return result.returncode, result.stdout, result.stderr

    def run_to_stdout(
        self,
        input_file: str,
        flags: list[str] = None
    ) -> tuple[int, str, str]:
        """Run with --stdout flag and capture XML output"""
        flags = flags or []
        if "--stdout" not in flags:
            flags.append("--stdout")

        return self.run(input_file, output_file=None, flags=flags)


@pytest.fixture
def cli_runner(script_path):
    """Fixture providing CLI runner helper"""
    return CLIRunner(script_path)


class StatsParser:
    """Helper to parse statistics from CLI output"""

    @staticmethod
    def parse(output: str) -> dict[str, int]:
        """
        Parse redaction statistics from stdout/stderr

        Returns:
            Dictionary with stat names and counts
        """
        stats = {}

        # Parse standard stats format
        patterns = {
            'secrets_redacted': r'Passwords/keys/secrets:\s+(\d+)',
            'certs_redacted': r'Certificates:\s+(\d+)',
            'ips_redacted': r'IP addresses:\s+(\d+)',
            'macs_redacted': r'MAC addresses:\s+(\d+)',
            'domains_redacted': r'Domain names:\s+(\d+)',
            'emails_redacted': r'Email addresses:\s+(\d+)',
            'urls_redacted': r'URLs:\s+(\d+)',
            'unique_ips_anonymised': r'Unique IPs anonymised:\s+(\d+)',
            'unique_domains_anonymised': r'Unique domains anonymised:\s+(\d+)',
        }

        import re
        for key, pattern in patterns.items():
            match = re.search(pattern, output)
            if match:
                stats[key] = int(match.group(1))

        return stats


@pytest.fixture
def stats_parser():
    """Fixture providing stats parser helper"""
    return StatsParser()


class XMLHelper:
    """Helper for XML operations"""

    @staticmethod
    def normalise_xml(xml_path: Path) -> ET.Element:
        """Parse and return normalised XML tree"""
        tree = ET.parse(xml_path)
        return tree.getroot()

    @staticmethod
    def xml_to_string(element: ET.Element) -> str:
        """Convert XML element to string"""
        return ET.tostring(element, encoding='unicode')

    @staticmethod
    def compare_xml_files(file1: Path, file2: Path) -> bool:
        """
        Compare two XML files semantically

        Returns True if they are equivalent
        """
        tree1 = ET.parse(file1)
        tree2 = ET.parse(file2)

        return XMLHelper._elements_equal(tree1.getroot(), tree2.getroot())

    @staticmethod
    def _elements_equal(e1: ET.Element, e2: ET.Element) -> bool:
        """Recursively compare two XML elements"""
        # Compare tags
        if e1.tag != e2.tag:
            return False

        # Compare text (strip whitespace for comparison)
        if (e1.text or '').strip() != (e2.text or '').strip():
            return False

        # Compare tail
        if (e1.tail or '').strip() != (e2.tail or '').strip():
            return False

        # Compare attributes
        if e1.attrib != e2.attrib:
            return False

        # Compare children
        if len(e1) != len(e2):
            return False

        return all(
            XMLHelper._elements_equal(c1, c2)
            for c1, c2 in zip(e1, e2)
        )


@pytest.fixture
def xml_helper():
    """Fixture providing XML helper"""
    return XMLHelper()


def create_temp_xml(content: str, tmp_path: Path) -> Path:
    """
    Create a temporary XML file with given content

    Args:
        content: XML content as string
        tmp_path: pytest tmp_path fixture

    Returns:
        Path to created file
    """
    xml_file = tmp_path / "test.xml"
    xml_file.write_text(content)
    return xml_file


@pytest.fixture
def create_xml_file(tmp_path):
    """Fixture that returns a function to create temp XML files"""
    def _create(content: str, filename: str = "test.xml") -> Path:
        xml_file = tmp_path / filename
        xml_file.write_text(content)
        return xml_file
    return _create


# ============================================================================
# Unit Test Fixtures (for direct PfSenseRedactor testing)
# ============================================================================

@pytest.fixture
def redactor_factory():
    """Factory for creating redactor instances with custom configuration

    Usage:
        def test_something(redactor_factory):
            redactor = redactor_factory(anonymise=True, keep_private_ips=False)
            result = redactor.redact_text("test")
    """
    from pfsense_redactor.redactor import PfSenseRedactor

    def _create(**kwargs):
        return PfSenseRedactor(**kwargs)
    return _create


@pytest.fixture
def basic_redactor(redactor_factory):
    """Basic redactor with default settings"""
    return redactor_factory()


@pytest.fixture
def anonymising_redactor(redactor_factory):
    """Redactor with anonymisation enabled"""
    return redactor_factory(anonymise=True)


@pytest.fixture
def aggressive_redactor(redactor_factory):
    """Redactor with aggressive mode enabled"""
    return redactor_factory(aggressive=True)


@pytest.fixture
def sample_ips():
    """Common IP addresses for testing"""
    return {
        'public_ipv4': '203.0.113.10',
        'private_ipv4': '192.168.1.1',
        'public_ipv6': '2001:db8::1',
        'link_local_ipv6': 'fe80::1',
        'ipv4_with_port': '203.0.113.10:8080',
        'ipv6_with_port': '[2001:db8::1]:8080',
        'ipv6_with_zone': 'fe80::1%eth0',
        'ipv6_with_zone_and_port': '[fe80::1%eth0]:8080',
    }


@pytest.fixture
def sample_domains():
    """Common domains for testing"""
    return {
        'ascii': 'example.com',
        'unicode': 'bücher.de',
        'punycode': 'xn--bcher-kva.de',
        'subdomain': 'api.example.com',
        'with_trailing_dot': 'example.com.',
        'wildcard': '*.example.com',
    }


@pytest.fixture
def sample_urls():
    """Common URLs for testing"""
    return {
        'http': 'http://example.com/path',
        'https': 'https://example.com:443/path',
        'with_ipv4': 'http://203.0.113.10:8080/api',
        'with_ipv6': 'http://[2001:db8::1]:8080/api',
        'with_credentials': 'https://user:pass@example.com/path',
    }


@pytest.fixture
def sample_macs():
    """Common MAC addresses for testing"""
    return {
        'standard': 'aa:bb:cc:dd:ee:ff',
        'cisco': 'aabb.ccdd.eeff',
        'uppercase': 'AA:BB:CC:DD:EE:FF',
    }


@pytest.fixture
def minimal_config(tmp_path):
    """Create minimal valid pfSense config"""
    config = tmp_path / "minimal.xml"
    config.write_text("""<?xml version="1.0"?>
<pfsense>
  <version>1.0</version>
</pfsense>
""")
    return config


@pytest.fixture
def config_with_secrets(tmp_path):
    """Create config with various secret types"""
    config = tmp_path / "secrets.xml"
    config.write_text("""<?xml version="1.0"?>
<pfsense>
  <system>
    <password>MySecretPassword123</password>
    <apikey>sk_live_1234567890abcdef</apikey>
  </system>
</pfsense>
""")
    return config


@pytest.fixture
def config_with_ips(tmp_path):
    """Create config with various IP addresses"""
    config = tmp_path / "ips.xml"
    config.write_text("""<?xml version="1.0"?>
<pfsense>
  <system>
    <dnsserver>8.8.8.8</dnsserver>
    <gateway>192.168.1.1</gateway>
    <ipv6addr>2001:db8::1</ipv6addr>
  </system>
</pfsense>
""")
    return config


@pytest.fixture
def config_with_domains(tmp_path):
    """Create config with various domains"""
    config = tmp_path / "domains.xml"
    config.write_text("""<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>firewall.example.com</hostname>
    <domain>example.org</domain>
  </system>
</pfsense>
""")
    return config
