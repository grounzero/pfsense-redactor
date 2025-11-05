# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.8] - 2025-11-05

### Security
- **FIX**: Added symlink security check for `--inplace` mode
  - Prevents following symlinks when using `--inplace` to avoid overwriting sensitive system files
  - Symlink check now occurs before file size validation to handle directory symlinks on Windows
  - Detects symlinks to regular files, directories, and broken symlinks
  - Shows symlink target in error message to help users understand the issue
  - Hardlinks continue to work (they're safe, unlike symlinks)
  - Added 10 tests in `tests/unit/test_symlink_security.py`
  - Prevents attack scenario: attacker replaces config.xml with `ln -s /etc/passwd config.xml`
- **FIX**: Invalid ports in URLs are now omitted to prevent malformed output
  - Previously, invalid ports (out of range, zero, negative, non-numeric) were appended without validation
  - Now omits invalid ports entirely, ensuring output URLs are always valid and parseable
  - Added debug logging when invalid ports are detected in URL netloc
  - Prevents malformed URLs that could bypass downstream filtering or cause parsing errors
  - Added 18 tests in `TestURLInvalidPortHandling`
- **FIX**: Enhanced whitespace validation in domain normalisation
  - Previously only checked for space character `' '`, allowing tabs, newlines, and other whitespace to bypass validation
  - Now uses regex `\s` to reject ANY whitespace character (space, tab, newline, carriage return, non-breaking space, etc.)
  - Prevents malformed domains like `"evil.com\texample.com"` from passing validation
  - Prevents potential bypass of suffix matching logic and allowlist validation
  - Updated comment to clarify "any whitespace" instead of "internal whitespace"
  - Added 9 tests covering all whitespace types in `TestDomainNormalisationSecurity`
- **FIX**: Added port range validation (1-65535) for IP addresses
  - Previously accepted invalid ports (0, greater than 65535) which could cause confusion or security issues
  - Port 0 (reserved) is now rejected and not stripped from IP addresses
  - Ports greater than 65535 are now rejected and not stripped from IP addresses
  - Leading zeros in port numbers are normalised (e.g., `:00080` becomes `:80`)
  - Validation applies to both `IPv4:port` and `[IPv6]:port` formats
  - Invalid ports in URLs are handled gracefully without crashes
  - Added 27 tests in `tests/unit/test_port_validation.py`

### Fixed
- **FIX**: Prevent re-redaction of RFC documentation IPs in anonymisation mode
  - RFC 5737 IPv4 ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) now recognised as masked values
  - RFC 3849 IPv6 range (2001:db8::/32) now recognised as masked values
  - Prevents re-redaction on subsequent runs, ensuring idempotent behaviour
  - Prevents mapping instability and statistics inflation
  - Only applies in `--anonymise` mode to avoid interfering with normal redaction
  - Defence-in-depth implementation across `_is_already_masked_host()`, `_mask_ip_like_tokens()`, `_normalise_masked_url()`, and `_anonymise_ip_for_url()`
- **FIX**: Fixed IP counter overflow in anonymisation mode
  - After 762 unique IPs, counter would wrap and create duplicate mappings (IP #763 → 192.0.2.1, same as IP #1)
  - Now falls back to RFC 1918 private range (10.0.0.0/8) for overflow addresses
  - Supports up to 16,777,978 unique IPv4 addresses (762 RFC 5737 + 16,777,216 RFC 1918)
  - IPv6 overflow (after 65535 addresses) falls back to RFC 4193 ULA range (fd00::/8)
  - Added warning logs at thresholds: 700, 750, 762 addresses used
  - Added warning on first overflow with explanation of fallback behaviour
  - Added 18 tests in `tests/unit/test_ip_overflow.py`
  - Verified no duplicate mappings occur across RFC and overflow ranges

### Security
- **FIX**: Added file path validation to prevent arbitrary file read/write operations
  - Blocks directory traversal attempts (`../../../etc/passwd`)
  - Blocks paths with null bytes (path traversal attack vector)
  - Blocks writing to sensitive system directories (`/etc`, `/sys`, `/proc`, `/Windows/System32`, etc.)
  - Blocks writing to critical system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, etc.)
  - Validates paths before any file operations (input, output, and in-place modes)
  - Resolves symbolic links to detect attempts to write to protected locations
  - By default, only allows relative paths and absolute paths to safe locations (home, CWD, temp directories)

### Added
- New `--allow-absolute-paths` flag to explicitly enable absolute path usage
  - Required for absolute paths outside safe locations (home, CWD, temp)
  - Still enforces protection against sensitive system directories
  - Useful for intentional absolute path operations
- New path validation functions:
  - `validate_file_path()`: Path security validation
  - `_get_sensitive_directories()`: Computes list of protected system directories
- 45 comprehensive tests for path validation:
  - 28 unit tests in `tests/unit/test_path_validation.py`
  - 17 integration tests in `tests/integration/test_path_security.py`
  - Tests cover directory traversal, null bytes, sensitive directories, symbolic links, and edge cases

### Changed
- Path validation now occurs before file existence checks
- In-place mode (`--inplace`) now validates paths with stricter output-level checks
- Dry-run mode now validates output paths for security (even though no write occurs)
- Error messages now clearly indicate when `--allow-absolute-paths` is required

## [1.0.7][] - 2025-11-03

### Fixed
- **CRITICAL FIX**: Fixed whitespace corruption in URL/email/FQDN redaction
  - `_redact_urls_safe`, `_redact_emails_safe`, and `_redact_fqdns_safe` were using `text.split()` and `' '.join()`
  - This collapsed all whitespace (including newlines) into single spaces, corrupting XML text content
  - Now uses `re.sub()` with callbacks to preserve original whitespace structure
  - Maintains ReDoS protection via length pre-filtering in the callback functions
- **CRITICAL FIX**: Fixed whitespace domain handling vulnerability in allowlist validation
  - Added `.strip()` to prevent allowlist bypass with whitespace-only domains (e.g., `"   "`)
  - Whitespace-only domains could previously match ANY domain in suffix matching
  - Added validation to reject domains with internal whitespace
  - Added 6 comprehensive tests in `TestDomainNormalisationSecurity`
- **MEDIUM FIX**: Fixed port stripping logic to validate IPv4 addresses
  - Now validates IP addresses using `ipaddress.ip_address()` before stripping ports
  - Prevents incorrect port stripping from non-IP tokens like `foo.bar.baz:8080`
  - Previously only checked for presence of dots, not valid IP format
  - Added 4 tests in `TestPortStrippingSecurity`
- **MEDIUM FIX**: Fixed overly broad sensitive attribute matching
  - Replaced substring matching with anchored regex patterns using word boundaries (`\b`)
  - Previously `'pass'` matched `compass_heading`, `'auth'` matched `author`, etc.
  - Now uses precise pattern: `\b(?:password|passwd|pass|key|secret|...)\b`
  - Prevents false positives whilst maintaining security for genuine sensitive attributes
  - Added 16 comprehensive tests in `TestSensitiveAttributeAnchoring`
- **ENHANCEMENT**: Prevent re-anonymisation of already-masked domains
  - `_is_already_masked_host()` now recognises `domain\d+\.example` pattern when `--anonymise` is enabled
  - Already-masked domains like `domain7.example` are no longer re-anonymised during processing
  - Ensures consistent handling of previously redacted configurations

### Added
- New `--quiet` / `-q` flag: Suppress progress messages (show only warnings and errors)
- New `--verbose` / `-v` flag: Show detailed debug information
- Flags are mutually exclusive and validated at runtime
- `ColouredFormatter` class for optional ANSI colour output
- `setup_logging()` function for configuring log levels and output streams
- New `--redact-url-usernames` CLI flag for enhanced URL credential redaction
  - Allows redacting sensitive usernames (e.g., `admin`, `root`) in URLs
  - Default behaviour: preserve usernames, always redact passwords (`ftp://user:REDACTED@host`)
  - With flag: redact both (`ftp://REDACTED:REDACTED@host`)
  - Added 7 tests in `TestURLUsernameRedaction`

### Changed
- **BREAKING**: Replaced `print()` statements with Python's `logging` module for better integration
  - All output now uses proper log levels (ERROR, WARNING, INFO, DEBUG)
  - Logs route to stdout by default, stderr when using `--stdout` mode
  - Removed `--stats-stderr` flag (no longer needed - logging handles routing automatically)
- Coloured log output when outputting to a TTY (auto-detected, disabled for pipes/redirects)
  - ERROR: Red, WARNING: Yellow, INFO: Green, DEBUG: Cyan
- Domain normalisation now strips whitespace before processing dots
- Port stripping now requires valid IPv4 address validation
- URL/email/FQDN redaction now uses `re.sub()` instead of tokenisation to preserve whitespace
- **IMPROVEMENT**: Simplified IPv6 documentation address mapping
  - `_counter_to_rfc_ip()` now uses cleaner wrapping logic: `h = (counter - 1) % 0xFFFF + 1`
  - Maps counters to single hextet (1..65535) with wrapping: `2001:db8::1` through `2001:db8::ffff`
  - More predictable and maintainable than previous two-hextet approach

### Removed
- `--stats-stderr` flag (replaced by automatic log routing in `--stdout` mode)

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

[1.0.7]: https://github.com/grounzero/pfsense-redactor/releases/tag/v1.0.7
[1.0.6]: https://github.com/grounzero/pfsense-redactor/releases/tag/v1.0.6
[1.0.5]: https://github.com/grounzero/pfsense-redactor/releases/tag/v1.0.5
[1.0.4]: https://github.com/grounzero/pfsense-redactor/releases/tag/v1.0.4
[1.0.3]: https://github.com/grounzero/pfsense-redactor/releases/tag/v1.0.3