"""pfSense XML Configuration Redactor

Safely removes sensitive information from pfSense config.xml exports before
they are shared with support, consultants, auditors, or AI tools for security analysis.
"""

from .redactor import PfSenseRedactor

__version__ = "1.0.0"
__all__ = ["PfSenseRedactor"]
