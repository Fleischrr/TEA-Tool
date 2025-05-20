"""Subclass of Port object representing optional data."""

from dataclasses import dataclass


@dataclass
class PortOptional:
    """
    Represents the optional metadata for a Port object.

    Retrieved from the SHODAN API.

    :ivar str name:
        The name of the optional info.

    :ivar str description:
        A description of the optional info.

    :ivar str created_at:
        The date and time when the opt was created.

    :ivar str modified_at:
        The date and time when the opt was last modified.

    """

    name: str
    description: str = ""
    created_at: str = ""
    modified_at: str = ""

    def __str__(self):
        """Return a string representation of the PortOptional object."""
        summary = self.description or ""

        if len(summary) > 100:
            summary = summary[:100] + "..."

        return f"{self.name}: {summary}"
