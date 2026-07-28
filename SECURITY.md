# Security Policy

## Reporting a Vulnerability

**Please report privately, not in a public issue.**

Use GitHub's private vulnerability reporting:

<https://github.com/grounzero/pfsense-redactor/security/advisories/new>

That channel stays private to the maintainers until an advisory is published.
For a redaction tool this matters more than usual: a report that a particular
secret survives redaction is, in effect, instructions for extracting that secret
from every configuration anyone has already shared.

If private reporting is unavailable to you, open a public issue saying only that
you have a security report and asking for a private channel. **Do not include
the details, and do not attach a real configuration.** A synthetic fragment with
the value replaced by a `CANARY_*` marker is exactly what is useful, and is safe
to send in the open.

**What to include**

1. What survives redaction, and in which mode
2. A minimal synthetic fragment that reproduces it
3. The version (`pfsense-redactor --version`) and platform
4. Potential impact, and a suggested fix if you have one

**What to expect**

- Acknowledgement of the report
- Coordinated disclosure: a fix, then an advisory
- Credit in the advisory and the changelog, unless you ask otherwise
- A CVE requested for anything that leaks material from a configuration a user
  believed had been redacted

This is a small, largely single-maintainer project. Response times depend on
availability rather than on a support commitment, and no service level is
offered or implied.

## Supported Versions

| Version | Supported                                     |
| ------- | --------------------------------------------- |
| 1.7.x   | ✅ Current release; security fixes land here first |
| 1.6.x   | ✅ Security fixes                              |
| < 1.6   | ❌ Upgrade                                     |

This table said `1.0.x` while the project shipped 1.2.0, which meant it named a
line that received nothing.

Older versions are not patched. The work in 1.3.0 through 1.4.1 changed
detection, output handling and failure behaviour substantially, and backporting
it to a 1.0 line would amount to shipping it again.

Versions before 1.3.0 have known false negatives documented in
[the changelog](CHANGELOG.md): private-key material could survive in an
unrecognised element or attribute while the run exited 0. If you are on one of
those, upgrade rather than wait for a patch.

## What this tool does and does not claim

Read [docs/security.md](docs/security.md) for the threat model and
[docs/verifying-output.md](docs/verifying-output.md) for how to check a result.
In short:

- The failure that matters is a **missed** secret, not an over-redacted one.
- `--strict` is a mode with no silent failure path. It is not a guarantee, and
  it is not described as certified, audit-grade, complete, or suitable for
  every third-party package schema.
- A clean scan from an independent tool such as gitleaks is a second opinion,
  not a certificate. On this project's own canary corpus, gitleaks reports no
  findings *before* any redaction.
- Independent verification reduces correlated failure. It does not eliminate
  false negatives.

## Security features

- Private-key PEM material redacted in every mode, wherever it appears,
  including through bounded Base64 and Base64URL decoding
- An independent verifier that re-reads the serialised output using rules
  maintained separately from the transformer's
- Verify-before-write: a failed gate produces no artefact at all
- Atomic `0600` writes, and refusal of output paths that reach the input, that
  are symbolic links, or that have more than one name
- Path traversal prevention and sensitive-directory protection
- ReDoS protection, bounded decoding, bounded nesting, bounded element size
- DOCTYPE and oversized-prolog refusal
- No runtime dependencies, which is the largest supply-chain reduction
  available to a tool of this kind

## Supply chain

- PyPI releases are published through **OIDC Trusted Publishing** only. No
  workflow contains an API-token fallback, and none should be added.
- Every third-party GitHub Action is pinned to an immutable commit SHA, with
  the corresponding release named in a comment beside it.
- The one workflow that can write to the repository runs no third-party action
  at all, and proposes its changes as a pull request rather than pushing.

## Security audit history

- **2026-07**: v1.3.0–v1.7.0 — external security review and remediation.
  Detection hardening, an independent verifier, verified atomic output, a
  fail-closed `--strict` mode, and supply-chain pinning. Status per finding in
  [the remediation tracker](docs/security-remediation-tracker.md).
- **2026-07**: v1.1.0 — secret detection coverage (pattern-based element
  matching, URL/blob scanning)
- **2025-12**: v1.0.8 — symlink security hardening
- **2025-11**: v1.0.7 — port validation improvements
- **2025-10**: v1.0.6 — ReDoS protection added
