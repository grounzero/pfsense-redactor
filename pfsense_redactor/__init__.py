"""pfSense XML Configuration Redactor

Safely removes sensitive information from pfSense config.xml exports before
they are shared with support, consultants, auditors, or AI tools for security analysis.
"""

import sys

# Require Python 3.9+ (for ET.indent and other features)
if sys.version_info < (3, 9):
    raise RuntimeError(
        "pfsense-redactor requires Python 3.9 or later. "
        f"You are using Python {sys.version_info.major}.{sys.version_info.minor}."
    )

__version__ = "1.0.7"

# pylint: disable=wrong-import-position
from .redactor import PfSenseRedactor, main, parse_allowlist_file

__all__ = ["PfSenseRedactor", "main", "parse_allowlist_file"]
