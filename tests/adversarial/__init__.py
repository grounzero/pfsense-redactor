"""Adversarial test suite - security review 2026-07

These tests assert the security property that *should* hold, not the behaviour
that currently does. Where a gap is real today the test carries
``@pytest.mark.xfail(strict=True)``, so:

- today it reports xfail and the suite stays green;
- the day someone closes the gap it reports XPASS, which strict xfail turns
  into a failure, forcing the marker to be removed.

A gap therefore cannot be closed silently, and cannot be reopened silently
either. Findings referenced as FINDING-nn map to
docs/security-review-2026-07.md.
"""
