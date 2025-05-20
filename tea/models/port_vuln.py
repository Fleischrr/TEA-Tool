"""Subclass of Port object representing a vulnerability."""

from dataclasses import dataclass


@dataclass
class PortVuln:
    """
    Represents a vulnerability for a Port object.

    Retrieved from the SHODAN API.

    :ivar str name:
        The name of the vulnerability.

    :ivar str created_at:
        The date and time when the vuln was created.

    :ivar str modified_at:
        The date and time when the vuln was last modified.
    """

    name: str
    created_at: str = ""
    modified_at: str = ""
