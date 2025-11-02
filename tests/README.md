# pfSense Redactor Test Suite

This directory contains the comprehensive test suite for the pfSense Redactor tool.

## Test Structure

The test suite is organised into three main categories:

```
tests/
├── unit/              # Unit tests for individual components
├── integration/       # Integration tests for CLI and end-to-end workflows
├── properties/        # Property-based tests for invariants
├── conftest.py        # Shared pytest fixtures and configuration
└── requirements.txt   # Test dependencies
```

### Unit Tests (`tests/unit/`)
- **test_focused_behaviour.py** - Focused tests for specific redaction behaviours
- **test_dry_run_verbose.py** - Tests for dry-run verbose mode
- **test_ip_handling.py** - IPv4 and IPv6 address handling tests
- **test_ipv6_zone_identifiers.py** - IPv6 zone identifier preservation tests
- **test_domain_handling.py** - Domain name and IDNA handling tests
- **test_url_handling.py** - URL parsing and redaction tests
- **test_sample_masking.py** - Sample collection and masking tests
- **test_security.py** - Security-related tests (ReDoS, input validation)

### Integration Tests (`tests/integration/`)
- **test_allowlist_features.py** - Allow-list functionality (CIDR, domains)
- **test_cli_behaviour.py** - CLI argument handling and modes
- **test_reference_snapshots.py** - Golden snapshot comparisons
- **test_statistics.py** - Redaction statistics accuracy

### Property Tests (`tests/properties/`)
- **test_invariants.py** - Property-based tests for system invariants

## Running Tests

### Prerequisites

1. **Activate the virtual environment:**
   ```bash
   cd /pfsense-redactor
   source .venv/bin/activate
   ```

2. **Install test dependencies:**
   ```bash
   pip install -r tests/requirements.txt
   ```

### Quick Start: Using run_tests.sh

The easiest way to run tests is using the provided shell script:

```bash
./run_tests.sh                    # Run all tests
./run_tests.sh --fast             # Run only fast tests (skip reference snapshots)
./run_tests.sh --parallel -v      # Run in parallel with verbose output
./run_tests.sh --update-reference # Regenerate reference files
./run_tests.sh --help             # Show all options
```

**Available options:**
- `--fast` - Run only fast tests (skip reference snapshots)
- `--slow` - Run only slow tests (reference snapshots)
- `--reference` - Run only reference snapshot tests
- `-v, --verbose` - Verbose output
- `-vv` - Very verbose output
- `-n, --parallel` - Run tests in parallel (requires pytest-xdist)
- `--update-reference` - Update reference files
- `-h, --help` - Show help message

### Running All Tests (Direct pytest)

Run the complete test suite (164 tests):

```bash
python -m pytest tests/ -v
```

### Running Specific Test Categories

**Unit tests only:**
```bash
python -m pytest tests/unit/ -v
```

**Integration tests only:**
```bash
python -m pytest tests/integration/ -v
```

**Property tests only:**
```bash
python -m pytest tests/properties/ -v
```

### Running Specific Test Files

```bash
python -m pytest tests/unit/test_focused_behaviour.py -v
python -m pytest tests/integration/test_allowlist_features.py -v
```

### Running Specific Tests

```bash
# Run a specific test function
python -m pytest tests/unit/test_ip_handling.py::TestIPv4Handling::test_ipv4_with_port_masking -v

# Run all tests in a class
python -m pytest tests/unit/test_ip_handling.py::TestIPv4Handling -v
```

### Useful Pytest Options

**Show detailed output:**
```bash
python -m pytest tests/ -v --tb=short
```

**Stop on first failure:**
```bash
python -m pytest tests/ -x
```

**Run tests in parallel (faster):**
```bash
python -m pytest tests/ -n auto
```

**Show test coverage:**
```bash
python -m pytest tests/ --cov=. --cov-report=html
```

**Run only failed tests from last run:**
```bash
python -m pytest tests/ --lf
```

**Collect tests without running them:**
```bash
python -m pytest tests/ --collect-only
```

## Test Fixtures

The test suite uses pytest fixtures defined in [`conftest.py`](conftest.py) for consistent test setup:

### Factory Fixtures
- **`redactor_factory()`** - Creates PfSenseRedactor instances with custom parameters
- **`basic_redactor()`** - Basic redactor with default settings
- **`anonymising_redactor()`** - Redactor with anonymise=True
- **`aggressive_redactor()`** - Redactor with aggressive=True

### CLI Fixtures
- **`cli_runner`** - Helper for running CLI commands
- **`create_xml_file`** - Creates temporary XML test files
- **`temp_output_dir`** - Temporary directory for test outputs
- **`script_path`** - Path to pfsense-redactor.py

### Test Data Fixtures
- **`sample_ips()`** - Common IP addresses for testing
- **`sample_domains()`** - Common domains for testing
- **`sample_urls()`** - Common URLs for testing
- **`sample_macs()`** - Common MAC addresses for testing
- **`sample_files`** - List of sample config files from test-configs/

### Configuration Fixtures
- **`minimal_config`** - Minimal valid pfSense config
- **`config_with_secrets`** - Config with various secret types
- **`config_with_ips`** - Config with various IP addresses
- **`config_with_domains`** - Config with various domains

## Writing New Tests

### Using Fixtures

```python
def test_something(cli_runner, create_xml_file, tmp_path):
    """Test description"""
    # Create test XML file
    xml_file = create_xml_file("""<?xml version="1.0"?>
    <pfsense>
      <system><password>secret</password></system>
    </pfsense>
    """)
    
    # Run CLI command
    output_file = tmp_path / "output.xml"
    exit_code, stdout, stderr = cli_runner.run(
        str(xml_file),
        str(output_file)
    )
    
    # Assertions
    assert exit_code == 0
    assert "[REDACTED]" in output_file.read_text()
```

### Using Redactor Factory

```python
def test_ip_masking(redactor_factory):
    """Test IP masking behaviour"""
    redactor = redactor_factory(keep_private_ips=False)
    
    text = "Server at 192.168.1.1"
    result = redactor.redact_text(text)
    
    assert "192.168.1.1" not in result
    assert "XXX.XXX.XXX.XXX" in result
```

## Test Status

Current test status: **164 tests passing** ✅

Run `python -m pytest tests/ -v` to verify all tests pass.

## Continuous Integration

Tests are automatically run on:
- Pull requests
- Commits to main branch
- Release tags

## Troubleshooting

### Tests fail with "fixture not found"
Make sure you're running tests from the project root directory and the virtual environment is activated.

### Import errors
Ensure test dependencies are installed:
```bash
pip install -r tests/requirements.txt
```

### Slow test execution
Use parallel execution:
```bash
python -m pytest tests/ -n auto
```

## Contributing

When adding new tests:
1. Place unit tests in `tests/unit/`
2. Place integration tests in `tests/integration/`
3. Use existing fixtures from `conftest.py` when possible
4. Follow the naming convention: `test_*.py` for files, `test_*` for functions
5. Add docstrings to explain what each test verifies
6. Ensure all tests pass before submitting a PR

## Reference Files

The `tests/reference/` directory contains golden snapshot files used by reference snapshot tests. These are automatically generated and should not be manually edited unless updating expected behaviour.