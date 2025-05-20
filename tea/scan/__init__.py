"""
The `tea.scan` package contains scanning functions for various types of scans.

The package is used by the TEA-Tool to perform the discovery and full scans functions.
"""

# /tea/scan/__init__.py
# Import the main scanning functions to simplify imports
from .asn_scanner import asn
from .discovery_scanner import discovery
from .domain_scanner import domain
from .full_scanner import full
from .ip_scanner import ip

__all__ = ["ip", "asn", "domain", "discovery", "full"]
