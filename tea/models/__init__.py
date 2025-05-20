"""
The `tea.models` package contains data classes that represent various data models.

The package is used by the TEA-Tool, these include `TargetHost`, `ASN`, and `Port`.
"""

# /tea/models/__init__.py
# Import the main classes to simplify imports
from .asn import ASN
from .port import Port
from .port_opt import PortOptional
from .port_vuln import PortVuln
from .target_host import TargetHost

__all__ = ["TargetHost", "ASN", "Port", "PortVuln", "PortOptional"]
