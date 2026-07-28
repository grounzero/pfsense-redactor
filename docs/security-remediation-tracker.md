# Security remediation tracker

[← Documentation index](../README.md#documentation)

Working record for the remediation of the July 2026 security review of
`pfsense-redactor` 1.2.0. One row per scoped finding: where it is fixed, what
proves it, and what changes for users.

The review report itself is not part of this repository. This page carries the
remediation state; finding identifiers are referenced by id only.

## Delivery sequence

Five stacked pull requests, each independently reviewable and each leaving the
repository in a working state.

| PR | Branch | Objective |
| --- | --- | --- |
| 1 | `security/secret-detection-hardening` | See key material the transformer previously walked past |
| 2 | `security/independent-output-verifier` | Re-read the serialised output with rules the transformer does not share |
| 3 | `security/verified-atomic-output` | Verify before anything becomes externally visible; write atomically at `0600` |
| 4 | `security/strict-public-sharing-mode` | `--strict`: fail closed, no implicit configuration, machine-readable verdict |
| 5 | `security/supply-chain-hardening` | Pin write-capable actions; keep OIDC the only release path |

## Baseline

Measured on `main` at `5e15f4c` before any production change:

```text
python -m pytest tests/ -q
825 passed, 1 skipped, 57 xfailed
```

After the adversarial suite and this page were committed (both add tests of
their own), the same command reports:

```text
829 passed, 1 skipped, 57 xfailed
```

That is the number each pull request below is compared against.

## Progress

| PR | Full suite | Xfails removed | Xfails remaining |
| --- | --- | --- | --- |
| 1 | 1059 passed, 1 skipped, 26 xfailed | 31 | 26 |
| 2 | 1106 passed, 1 skipped, 26 xfailed | 0 | 26 |
| 3 | 1153 passed, 1 skipped, 18 xfailed | 8 | 18 |
| 4 | 1205 passed, 1 skipped, 9 xfailed | 9 | 9 |
| 5 | (measured below) | 0 | 9 |

Every confirmed gap carries a `xfail(strict=True)` marker naming its finding id,
so closing one turns its test into a failure until the marker is removed.

## Finding status

Status values: `fixed`, `partial`, `deferred`, `not planned`.

| Finding | Target PR | Existing test | New tests | Behaviour change | Compatibility impact | Status |
| --- | --- | --- | --- | --- | --- | --- |
| 01 PEM in unknown element retained | 1 | `test_redaction_gaps.py::TestKeyMaterialSurvival::test_pem_in_unknown_element_is_redacted` | private-key header matrix, log/preview leak checks | Private-key PEM is redacted in every mode, whatever element holds it | Values previously retained are now `[REDACTED_CERT_OR_KEY]` | fixed |
| 02 PEM in attribute retained | 1 | `…::test_pem_in_attribute_is_redacted` | attribute PEM, multiline, whitespace | Same, for attribute values | As above | fixed |
| 03 Encoded key material never decoded | 1 | `…::test_base64_wrapped_pem_is_redacted`, `…::test_double_base64_wrapped_pem_is_redacted` | bounded-decode unit suite | Bounded Base64/Base64URL inspection, depth 3 | Encoded key blobs are now redacted | fixed |
| 04 Single-character-class blobs invisible | 1 | `test_redaction_gaps.py::TestEntropyDetectorBlindSpots` (3 cases) | hex/uppercase/lowercase/negative corpus | Long uniform values are detected by length and entropy | More values reported as retained; more redacted under `--aggressive` | fixed |
| 05 JWTs invisible | 1 | `…::test_jwt_is_noticed` | JWT positive and negative corpus | JWT-like values are secrets in every mode | JWTs are redacted rather than retained | fixed |
| 09 Credential-bearing element names missed | 1 | `TestNameCoverage::test_unmatched_secret_tags_are_matched` (13 cases) | deny-list regression | 13 further element names classified as secret-bearing | Elements previously kept are now redacted | fixed |
| 10 Element and attribute patterns disagree | 1 | `TestNameCoverage::test_element_and_attribute_patterns_agree` (9 cases) | parity law | One shared predicate for both | Attribute and element handling now agree | fixed |
| 21 No independent verification | 2 | `test_assurance_signals.py::TestFailClosed::test_retained_key_material_fails_the_run` | defect-injection suite | Separate verifier re-reads serialised output | New module; advisory in PR 2, enforcing in PR 3 | fixed |
| 15 Input can be overwritten by output | 3 | `test_filesystem_safety.py::TestInputPreservation` (2 cases) | device/inode identity cases | Same-file output refused | `in.xml in.xml --force` now fails | fixed |
| 16 Output symlink followed | 3 | `…::test_output_symlink_pointing_at_input_is_refused` | symlink destination cases | Symlink output refused | Writing through a symlink now fails | fixed |
| 17 `--inplace` without `--force` | 3 | `…::test_inplace_requires_explicit_consent` | help/enforcement parity | `--inplace` requires `--force` | Scripts using bare `--inplace` must add `--force` | fixed |
| 18 Output is world-readable | 3 | `TestWriteSafety::test_output_is_not_world_readable` | mode assertions | Output created `0600` | Downstream readers may need explicit permissions | fixed |
| 19 Writes are not atomic | 3 | `TestWriteSafety` (2 cases) | fsync/replace failure injection | Temp file, `fsync`, `os.replace` | Hard-linked destinations are replaced, not written through | fixed |
| 22 `--fail-on-warn` writes before failing | 3 | `test_assurance_signals.py::TestFailClosed::test_fail_on_warn_writes_no_output` | verdict-before-write cases | Verify, then write | A failing gate no longer leaves an artefact | fixed |
| 13 Unbounded recursion on nesting | 4 | `test_parser_limits.py::TestRecursionBounds` (2 cases) | depth-limit cases | Depth bound, refusal instead of `RecursionError` | Very deep documents are refused | fixed |
| 14 Oversized text silently truncated | 4 | `TestTextSizeBounds::test_oversized_text_is_not_silently_truncated` | oversized-value cases | Oversized text replaced, not truncated; refused under `--strict` | Oversized elements change representation | fixed |
| 23 Only exit codes 0 and 1 | 4 | `TestFailClosed::test_exit_codes_distinguish_failure_kinds` | exit-code matrix | Distinct codes 0–6 | Non-zero remains non-zero; specific values are new | fixed |
| 24 Config `<version>` never inspected | 4 | `TestUnsupportedInput::test_unsupported_config_version_is_reported` | version-report cases | Version reported; refused under `--strict` | Unknown versions are named on stderr | fixed |
| 25 Implicit allow-lists | 4 | `TestImplicitConfiguration` (2 cases) | strict-mode discovery cases | Always announced; disabled under `--strict` | Extra stderr line in scripted modes | fixed |
| 26 No machine-readable report | 4 | `TestMachineReadableAssurance::test_a_structured_report_is_available` | schema and permission cases | `--report-json` | New optional flag | fixed |
| 27 Corpus score cannot see encoded survivors | 4 | `test_encoded_canary_scoring.py::TestCorpusScoringIsIncomplete` | benchmark documentation | Benchmark states the mode it measures | Documentation only | partial |
| SC-01 Action pinned to a moving branch | 5 | — (workflow) | workflow assertions | SHA-pinned, gated push | Snapshot workflow gains pre-push checks | fixed |
| SC-02 Dormant PyPI token | 5 | — (repository setting) | — | OIDC remains the only path | Requires a manual revocation | partial |
| SC-03 Ruleset requires no checks | 5 | — (repository setting) | — | Documented required checks | Requires administrator action | deferred |
| 29 Documentation drift | 5 | `tests/unit/test_docs_links.py` | documentation assertions | Corrected `/tmp`, bandit, version, reporting channel | Documentation only | fixed |

## Manual administrator actions

None of these can be made from a pull request. They are listed here rather than
marked done, because claiming a repository setting was changed when it was not
is worse than leaving it open.

| Action | Status | Why it is not in the code |
| --- | --- | --- |
| Revoke `PYPI_API_TOKEN` on PyPI and delete the repository secret | **Outstanding** | A repository secret is a settings-page object. No workflow references the name any more, and a test asserts none may, but the secret itself is still configured and still exposed to every workflow running in the trusted context |
| Verify the PyPI Trusted Publisher entry names this repository and the `pypi` environment | **Outstanding** | Settings on pypi.org |
| Enable private vulnerability reporting | **Outstanding** | `SECURITY.md` now points reporters at GitHub's private advisory form; that form has to be switched on in repository settings or the link is a dead end |
| Require the `tests` and `pylint` checks on `main` | **Outstanding** | The `main-protect` ruleset has no `required_status_checks` rule at all, so the 18-cell matrix, CodeQL and the structure gate are advisory at merge time |
| Require at least one approving review, or record that this is a sole-maintainer project and CI is the only gate | **Outstanding** | `required_approving_review_count` is 0 |
| Review unconditional administrator bypass on `main` | **Outstanding** | Admins currently bypass the ruleset entirely, so a security-critical change can be self-merged with failing tests |
| Add protection rules to the `pypi` deployment environment | **Outstanding** | The environment exists and is referenced by the release workflow; it has no reviewers or wait timer |

The workflow-side halves of these — SHA pinning, removing the third-party push
action, the pre-commit gates, and keeping OIDC the only publishing path — are
done and are asserted by `tests/unit/test_workflow_security.py`.

## Findings not scoped for this sequence

These remain open with their `xfail(strict=True)` markers intact. They are
recorded here so the remaining risk is visible rather than implied.

| Finding | Why it is not in this sequence |
| --- | --- |
| 06 Embedded JSON never parsed | Depends on the name predicate unified in PR 1; a JSON walker is a separate design decision |
| 07 CDATA free text | A restatement of 11 rather than a separate mechanism |
| 08 Element tails only under `--aggressive` | Defence in depth against XML pfSense does not emit |
| 11 Identifier redaction gated on a tag list | Changing the default is a product decision with a real compatibility cost |
| 12 Preview leaks the network and registrable domain | Privacy rather than credential exposure; needs a preview format decision |
| 20 Input accepted on `st_size` alone | Diagnosis quality; both cases are already refused |
| 28 Vacuous PEM invariant | Superseded in practice by `test_encoded_canary_scoring.py::TestPemInvariantIsNotVacuous`, which asserts the same invariant non-vacuously |
| 30 Stray directory from an isolated test | Test hygiene, no product impact |
