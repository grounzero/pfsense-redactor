"""Version checker for pfsense-redactor

Checks PyPI for the latest version and provides upgrade instructions
based on detected installation method.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import NamedTuple
import logging


# Installation methods that provide full upgrade instructions
COMMON_INSTALL_METHODS = ('pipx', 'venv', 'user')


class VersionInfo(NamedTuple):
    """Version information from PyPI"""
    current: str
    latest: str
    update_available: bool


class InstallationMethod(NamedTuple):
    """Detected installation method and upgrade command"""
    method: str
    upgrade_command: str


def get_current_version() -> str:
    """Get the current installed version"""
    try:
        # Use importlib.metadata to avoid cyclic import
        import importlib.metadata
        return importlib.metadata.version('pfsense-redactor')
    except Exception:  # pylint: disable=broad-except
        # Fallback: try to read from __init__.py directly
        try:
            init_file = Path(__file__).parent / '__init__.py'
            with open(init_file, 'r', encoding='utf-8') as file_handle:
                for line in file_handle:
                    if line.startswith('__version__'):
                        # Extract version from __version__ = "x.y.z"
                        return line.split('=')[1].strip().strip('"').strip("'")
        except Exception:
            pass
        return "unknown"


def check_pypi_version(timeout: int = 5) -> str | None:
    """Check PyPI for the latest version

    Args:
        timeout: Request timeout in seconds

    Returns:
        Latest version string or None if check failed
    """
    logger = logging.getLogger('pfsense_redactor')

    try:
        url = "https://pypi.org/pypi/pfsense-redactor/json"
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'pfsense-redactor-version-checker'}
        )

        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode('utf-8'))
            return data['info']['version']

    except urllib.error.HTTPError as err:
        logger.debug("HTTP error checking PyPI: %s", err)
        return None
    except urllib.error.URLError as err:
        logger.debug("Network error checking PyPI: %s", err)
        return None
    except (json.JSONDecodeError, KeyError) as err:
        logger.debug("Error parsing PyPI response: %s", err)
        return None
    except Exception as err:
        logger.debug("Unexpected error checking PyPI: %s", err)
        return None


def compare_versions(current: str, latest: str) -> bool:
    """Compare version strings to check if update is available

    Args:
        current: Current version string (e.g., "1.0.8")
        latest: Latest version string from PyPI

    Returns:
        True if update is available, False otherwise
    """
    if current == "unknown" or latest == "unknown":
        return False

    try:
        # Simple comparison - split by dots and compare as tuples
        current_parts = tuple(int(x) for x in current.split('.'))
        latest_parts = tuple(int(x) for x in latest.split('.'))
        return latest_parts > current_parts
    except (ValueError, AttributeError):
        return False


def detect_installation_method() -> InstallationMethod:
    """Detect how pfsense-redactor was installed

    Returns:
        InstallationMethod with method name and upgrade command
    """
    # Check if running in pipx environment
    if 'PIPX_HOME' in os.environ or 'pipx' in sys.prefix:
        return InstallationMethod(
            method="pipx",
            upgrade_command="pipx upgrade pfsense-redactor"
        )

    # Check if running in a virtual environment
    if hasattr(sys, 'real_prefix') or (
            hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    ):
        return InstallationMethod(
            method="venv",
            upgrade_command="pip install --upgrade pfsense-redactor"
        )

    # Check if installed as editable (development mode)
    try:
        import importlib.metadata
        dist = importlib.metadata.distribution('pfsense-redactor')
        # Use the public files() API to check if this is an editable install
        if dist.files and any(f.name == 'direct_url.json' for f in dist.files):
            # Has direct_url.json which indicates editable or direct install
            # Check if it's a local directory (editable install)
            direct_url_data = json.loads(dist.read_text('direct_url.json'))
            if direct_url_data.get('dir_info', {}).get('editable'):
                return InstallationMethod(
                    method="source",
                    upgrade_command="git pull && pip install -e ."
                )
    except (ImportError, AttributeError, ValueError, TypeError, KeyError, FileNotFoundError):
        # importlib.metadata not available, no direct_url.json, or parsing error
        pass

    # Check if installed in user site-packages
    try:
        import site
        import importlib.metadata
        user_site = site.getusersitepackages()
        dist = importlib.metadata.distribution('pfsense-redactor')
        # Get the location using the metadata's locate_file method
        dist_files = dist.files
        if dist_files and user_site:
            # Check if any of the files are in user site-packages
            first_file = dist_files[0]
            location = first_file.locate().resolve().parent
            # Navigate up to find the site-packages directory
            # Stop at root (location.parent == location) or when we find site-packages
            while location.name not in ('site-packages', 'dist-packages') and location != location.parent:
                location = location.parent
            if location.is_relative_to(Path(user_site).resolve()):
                # Installed in user site-packages
                return InstallationMethod(
                    method="user",
                    upgrade_command="pip install --user --upgrade pfsense-redactor"
                )
    except (ImportError, AttributeError, ValueError, TypeError, OSError, IndexError):
        # site/importlib.metadata not available, or path resolution failed
        pass

    # Default/unknown method
    return InstallationMethod(
        method="pip",
        upgrade_command="pip install --upgrade pfsense-redactor"
    )


def get_version_info() -> VersionInfo | None:
    """Get version information comparing current vs. latest

    Returns:
        VersionInfo or None if check failed
    """
    current = get_current_version()
    latest = check_pypi_version()

    if latest is None:
        return None

    update_available = compare_versions(current, latest)

    return VersionInfo(
        current=current,
        latest=latest,
        update_available=update_available
    )


def print_version_check(verbose: bool = False) -> bool:
    """Print version check results

    Args:
        verbose: If True, show detailed information

    Returns:
        True if check was successful, False otherwise
    """
    logger = logging.getLogger('pfsense_redactor')

    version_info = get_version_info()

    if version_info is None:
        logger.error("[!] Error: Could not connect to PyPI to check for updates")
        logger.info("    Check your internet connection or try again later")
        return False

    # Print version information
    logger.info("Current version: %s", version_info.current)
    logger.info("Latest version:  %s", version_info.latest)
    logger.info("")

    if version_info.update_available:
        # Detect installation method
        install_method = detect_installation_method()

        logger.info("[i] Update available!")
        logger.info("")
        logger.info("To upgrade:")
        logger.info("  %s", install_method.upgrade_command)

        if verbose or install_method.method not in COMMON_INSTALL_METHODS:
            logger.info("")
            logger.info("For other installation methods, see:")
            logger.info("  https://github.com/grounzero/pfsense-redactor#installation")
    else:
        logger.info("[✓] You are using the latest version")

    return True
