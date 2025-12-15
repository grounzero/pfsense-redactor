# Security Policy

## Supported Versions

| Version | Supported              |
| ------- | ---------------------- |
| 1.0.x   | ✅ Security updates    |
| < 1.0   | ❌ No longer supported |

## Reporting a Vulnerability

**What to Include**:

1. Detailed description of the vulnerability
2. Steps to reproduce
3. Potential impact assessment
4. Suggested fix (if available)

**Disclosure Policy**:

- We follow coordinated disclosure
- Security fixes are released ASAP
- CVEs are requested for significant vulnerabilities
- Credit given to reporters (unless anonymity requested)

## Security Features

pfSense Redactor includes multiple security protections:

- Path traversal prevention
- Symlink attack mitigation
- ReDoS (Regular Expression DoS) protection
- Input validation for all file operations
- No external dependencies (reduces supply chain risk)

## Security Audit History

- **2025-12**: v1.0.8 - Symlink security hardening
- **2025-11**: v1.0.7 - Port validation improvements
- **2025-10**: v1.0.6 - ReDoS protection added
