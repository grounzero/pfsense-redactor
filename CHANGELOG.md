# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.6][] - 2025-11-02

### Security
- **CRITICAL FIX**: Extended URL regex to handle non-HTTP protocols (FTP, FTPS, SFTP, SSH, Telnet, File, SMB, NFS)
  - Previously only HTTP/HTTPS URLs were matched, allowing credentials in `ftp://user:pass@host` URLs to bypass redaction
  - Credentials in non-HTTP URLs would have leaked through the bare FQDN redaction path
  - All protocol URLs now properly redact passwords whilst preserving usernames and structure
- **CRITICAL FIX**: URLs without hostnames (e.g., `file:///path`) are now preserved unchanged
  - Previously `file:///path` would be incorrectly transformed to `file://example.com/path`
  - This changed URL semantics from local filesystem to network file share
  - Added early return in `_mask_url()` when `hostname` is `None` or empty
- **ENHANCEMENT**: Expanded email regex to support RFC 5322 special characters
  - Now matches emails with `!#$&'*/=?^`{|}~` in local part (e.g., `user!test@example.com`)
  - Maintains ReDoS protection with limited repetitions
  - Previous regex only matched `[A-Za-z0-9._%+-]`, missing many legal email addresses

### Added
- Module-level exports control via `__all__` (PfSenseRedactor, main, parse_allowlist_file)
- Python 3.9+ version check at module import time with clear error message
- Cached IDNA encoding using `@functools.lru_cache(maxsize=256)` for improved performance
- Type hint for maskers dictionary: `dict[str, Callable[[str], str]]`
- XML comment in output files: `<!-- Redacted using pfsense-redactor v1.0.6 -->`
- 14 comprehensive tests for URL handling:
  - 8 tests for non-HTTP protocol URL redaction
  - 6 tests for hostnameless URL preservation

### Changed
- Updated version to 1.0.6 in both `__init__.py` and `pyproject.toml`
- Updated all test reference files to include redaction comment


## [1.0.5][] - 2025-11-02

### Changed
- Updated installation documentation in README to address `externally-managed-environment` error
- Added installation alternatives for macOS and modern Linux distributions:
  - pipx installation (recommended for CLI tools)
  - Virtual environment setup
  - User space installation
- Improved source installation instructions with separate options for development and virtual environment setups

## [1.0.4][] - 2025-11-02

### Changed
- Upgraded minimum Python version from 3.8 to 3.9
- Modernised type hints using `from __future__ import annotations` and PEP 604 union syntax (`X | Y`)
- Replaced all `typing` module imports with built-in types (`list`, `dict`, `tuple`, etc.)
- Refactored code to eliminate pylint warnings and improve maintainability
- Removed `ET.indent()` try/except block (now available in Python 3.9+)

### Added
- Linter configurations:
  - `.pylintrc` for production code (strict)
  - `.pylintrc-tests` for test code (relaxed)
  - `.bandit` for security linting

### Fixed
- Consistent XML indentation across Python versions
- All pylint, Prospector, and Bandit warnings resolved
- CI/CD workflows updated to test Python 3.9-3.13

## [1.0.3][] - 2025-11-02

### Added
- Initial PyPI release
- Python package structure with proper packaging configuration
- Command-line tool `pfsense-redactor` installable via pip
- Comprehensive redaction of sensitive pfSense configuration data:
  - Passwords, pre-shared keys, and API tokens
  - TLS/OpenVPN certificates and private keys
  - SNMP community strings and RADIUS secrets
  - Public IP addresses (with optional private IP preservation)
  - Domain names and email addresses
  - MAC addresses
  - URLs (with structure preservation)
- Multiple operational modes:
  - Default mode: Safe redaction for sharing
  - `--keep-private-ips`: Preserve RFC1918/ULA addresses
  - `--anonymise`: Consistent placeholder mapping for topology analysis
  - `--aggressive`: Comprehensive scrubbing of all fields
- Allow-list support for preserving known public services:
  - IP addresses and CIDR ranges
  - Domain names with suffix matching
  - IDNA/punycode support for internationalised domains
  - Default allow-list files (`.pfsense-allowlist`)
- Dry-run modes:
  - `--dry-run`: Statistics preview
  - `--dry-run-verbose`: Statistics with safely masked samples
- Smart handling of pfSense-specific structures:
  - XML namespaces
  - VPN configurations (IPSec, OpenVPN, WireGuard)
  - IPv6 zone identifiers
  - Firewall rules and gateway configurations
- Comprehensive test suite:
  - Unit tests for core functionality
  - Integration tests for CLI behaviour
  - Property-based tests for invariants
  - Reference snapshot tests
- Documentation:
  - Detailed README with usage examples
  - Publishing guide for maintainers
  - MIT licence

### Technical Details
- Python 3.8+ support
- Zero external dependencies (uses only standard library)
- Format-preserving redaction where possible
- Topology-aware anonymisation with consistent aliases
- Security-first design with comprehensive pattern matching

### Installation
```bash
pip install pfsense-redactor
```

### Usage
```bash
# Basic usage
pfsense-redactor config.xml

# Preserve private IPs (recommended for support/AI analysis)
pfsense-redactor config.xml --keep-private-ips

# Anonymise with consistent placeholders
pfsense-redactor config.xml --anonymise

# Preview changes without modifying files
pfsense-redactor config.xml --dry-run-verbose
```

[1.0.6]: https://github.com/grounzero/pfsense-redactor/releases/tag/v1.0.6
[1.0.5]: https://github.com/grounzero/pfsense-redactor/releases/tag/v1.0.5
[1.0.4]: https://github.com/grounzero/pfsense-redactor/releases/tag/v1.0.4
[1.0.3]: https://github.com/grounzero/pfsense-redactor/releases/tag/v1.0.3