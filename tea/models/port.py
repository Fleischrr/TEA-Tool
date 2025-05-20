"""Port dataclass for storing network port information."""

from dataclasses import dataclass, field

from .port_opt import PortOptional
from .port_vuln import PortVuln


@dataclass
class Port:
    """
    Represents a network port with relevant metadata.

    This includes protocol, hostnames, running service,
    HTTP status, vulnerabilities, and more.

    :ivar int number:
        The numeric port (e.g., 80, 443).

    :ivar str protocol:
        Optional. The protocol (e.g., "tcp", "udp").

    :ivar list[str] hostnames:
        Associated hostnames. Optional.

    :ivar str service:
        Optional. Associated service (e.g., "Apache", "Nginx").

    :ivar str banner:
        Optional. The related banner.

    :ivar int | None http_status:
        Optional. The HTTP status code.

    :ivar list[PortVuln] vulns:
        Optional. Associated known vulnerabilities or CVE IDs (e.g. CVE-2021-44228).

    :ivar list[PortOptional] opts:
        Optional. Extra information, possibly weaknesses or experimental data. (e.g. Heartbleed).

    :ivar str created_at:
        The date and time when the port was created.

    :ivar str modified_at:
        The date and time when the port was last modified.
    """

    number: int
    protocol: str = ""
    hostnames: list[str] = field(default_factory=list)
    service: str = ""
    banner: str = ""
    http_status: int | None = None
    vulns: list[PortVuln] = field(default_factory=list)
    opts: list[PortOptional] = field(default_factory=list)
    created_at: str = ""
    modified_at: str = ""

    def __post_init__(self) -> None:
        """Validate the port number to ensure it is an integer between 1 and 65535."""
        if not isinstance(self.number, int) or not (1 <= self.number <= 65535):
            raise ValueError("Port must be an integer between 1 and 65535")

    def __repr__(self) -> str:
        """
        Return the port number as a string.

        :return: The port number string.
        :rtype: str
        """
        return str(self.number)

    def __str__(self) -> str:
        """
        Return a human-readable string with detailed information about the port.

        :return: A string with detailed information about the port.
        :rtype: str
        """
        return (
            f"Port {self.number} has following information:\n"
            f"`->\tPort number: {self.number}\n"
            f"\tProtocol: {self.protocol}\n"
            f"\tHostname(s): {', '.join(self.hostnames)}\n"
            f"\tService: {self.service}\n"
            f"\tVuln(s): {', '.join(vuln.name for vuln in self.vulns)}\n"
            f"\tOpt(s): {', '.join(opt.name for opt in self.opts)}\n"
            f"\tHTTP status: {self.http_status}\n"
            f"\tHTTP header:\n"
            + (
                "\n".join(f"\t\t{line}" for line in self.http_header.splitlines())
                if self.http_header
                else ""
            )
        )
