"""Decode-aware canary scanner

The shipped corpus score in tests/integration/test_canary_corpus.py counts
survivors with a literal ``CANARY_[A-Z0-9_]+`` regex over the output. Anything
the config author encoded is therefore invisible to it: the base64 blob at
tests/corpus/canary-corpus.xml:105 decodes to a CANARY marker, is provably
retained in default mode, and still does not count against the 44/46 score.

This module finds markers through base64 layers so a leak cannot hide behind an
encoding. It is deliberately separate from the redactor: a verifier that shares
the transformer's assumptions cannot catch the transformer's mistakes.

Usable as a filter as well as an import::

    pfsense-redactor config.xml --stdout | python tests/adversarial/decode_scan.py
"""
from __future__ import annotations

import base64
import binascii
import re
import sys

# Base64-ish runs long enough to carry something worth hiding. 24 rather than
# 32: 'CANARY_ADV05' padded to a base64 quantum is shorter than a key blob, and
# the cost of decoding a few extra runs is nothing.
_B64_RUN = re.compile(r'[A-Za-z0-9+/=_\-]{24,}')

# Matches the corpus convention (CANARY_FOO) and this suite's (CANARY_ADV01_X).
MARKER_RE = re.compile(r'CANARY_[A-Z0-9_]+')

# Three layers covers single, double and triple wrapping. Unbounded recursion
# on attacker-supplied text is the mistake this file exists to look for
# elsewhere, so it is not repeated here.
MAX_DECODE_DEPTH = 3


def _decode_candidates(text: str) -> list[str]:
    """Every base64-ish run in `text`, decoded, dropping what does not decode"""
    out = []
    for run in _B64_RUN.findall(text):
        # urlsafe first, then standard: the two differ only in - _ vs + /, and
        # trying both means a URL-safe token is not missed.
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                padded = run + '=' * (-len(run) % 4)
                decoded = decoder(padded.encode('ascii'))
            except (binascii.Error, ValueError):
                continue
            try:
                out.append(decoded.decode('utf-8', errors='replace'))
            except UnicodeDecodeError:  # pragma: no cover - errors='replace'
                pass
            break
    return out


def find_markers(text: str, max_depth: int = MAX_DECODE_DEPTH) -> set[str]:
    """Canary markers in `text`, literal or reachable by base64 decoding

    Also searches the whitespace-stripped form, so a marker broken across lines
    inside one element is found. That is how a real secret survives a
    line-oriented scanner, and it is how this one is meant not to.
    """
    found: set[str] = set()
    layers = [text]

    for _ in range(max_depth + 1):
        if not layers:
            break
        next_layers = []
        for layer in layers:
            found.update(MARKER_RE.findall(layer))
            found.update(MARKER_RE.findall(re.sub(r'\s+', '', layer)))
            next_layers.extend(_decode_candidates(layer))
        layers = next_layers

    return found


def find_key_material(text: str) -> set[str]:
    """PEM header labels in `text`, literal or reachable by base64 decoding

    Separate from find_markers because key material is recognisable without a
    planted marker, and is the thing whose survival matters most.
    """
    pem = re.compile(r'-----BEGIN ([A-Z0-9 ]+)-----')
    found: set[str] = set()
    layers = [text]

    for _ in range(MAX_DECODE_DEPTH + 1):
        if not layers:
            break
        next_layers = []
        for layer in layers:
            found.update(pem.findall(layer))
            next_layers.extend(_decode_candidates(layer))
        layers = next_layers

    return found


def main() -> int:
    """Report markers and key material found on stdin"""
    data = sys.stdin.read()
    markers = sorted(find_markers(data))
    keys = sorted(find_key_material(data))

    for marker in markers:
        print(f"MARKER   {marker}")
    for label in keys:
        print(f"KEY      BEGIN {label}")

    if markers or keys:
        print(f"\n{len(markers)} marker(s), {len(keys)} key type(s) survived.")
        return 1

    print("nothing found")
    return 0


if __name__ == '__main__':
    sys.exit(main())
