"""TargetHost dataclass for storing target host information."""

from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import IPv4Address

from .asn import ASN
from .port import Port


@dataclass
class TargetHost:
    """
    Represents a target host in a network scan.

    This includes IP address, associated hostnames, open ports,
    operating system, domain, organization and ASN.

    :ivar IPv4Address ip:
        The IPv4 address of the target host.

    :ivar list[str] hostnames:
        List of hostnames associated with the target IP. Optional.

    :ivar list[models.Port] ports:
        List of open ports for the target IP.
        Based on the `models.Port` dataclass. Optional.

    :ivar str os:
        The Operating System of the target IP. Optional.

    :ivar str domain:
        The domain of the target IP. Optional.

    :ivar str org:
        The organization of the target IP. Optional.

    :ivar ASN asn:
        The Autonomous System Number (ASN) of the target IP.
        Based on the `models.ASN` dataclass. Optional.
    """

    ip: IPv4Address
    hostnames: list[str] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    os: str = ""
    domain: str = ""
    org: str = ""
    asn: ASN | None = None
    created_at: str = str(datetime.now().isoformat())
    modified_at: str = created_at

    def __post_init__(self) -> None:
        """Sorts the list of ports in ascending order after initialization."""
        self.sort_ports()

    def add_hostname(self, hostname: str) -> None:
        """
        Add a single hostname to the TargetHost object. Avoids duplicates.

        :param hostname: A hostname associated with the target IP.
        :type hostname: str
        """
        if hostname not in self.hostnames:
            self.hostnames.append(hostname)

    def add_hostnames(self, hostnames: list[str]) -> None:
        """
        Add a list of hostnames to the TargetHost object. Avoids duplicates.

        :param hostnames: A list of hostnames associated with the target IP.
        :type hostnames: list[str]
        """
        for hostname in hostnames:
            self.add_hostname(hostname)

    def add_port(self, port: int) -> None:
        """
        Add a single port to the TargetHost object. Avoids duplicates.

        :param port: A port number (1-65535) associated with the target IP.
        :type port: int
        """
        port_obj: Port = Port(port)
        if port_obj not in self.ports:
            self.ports.append(port_obj)
        self.sort_ports()

    def add_ports(self, ports: list[int]) -> None:
        """
        Add a list of ports to the TargetHost object. Avoids duplicates.

        :param ports: A list of port numbers (1-65535) associated with the target IP.
        :type ports: list[int]
        """
        for port in ports:
            self.add_port(port)
        self.sort_ports()

    def sort_ports(self) -> None:
        """Sorts the list of open ports in ascending order."""
        self.ports.sort(key=lambda x: x.number)

    def __str__(self) -> str:
        """
        Return a formatted string representation of the TargetHost object.

        :return: A formatted string representation of the TargetHost object.
        :rtype: str
        """
        return (
            f"IP:\t\t\t\t{self.ip}\n"
            f"Hostname(s):\t{', '.join(self.hostnames)}\n"
            f"Port(s):\t\t{', '.join(repr(port) for port in self.ports)}\n"
            f"OS:\t\t\t\t{self.os}\n"
            f"Domain:\t\t\t{self.domain}\n"
            f"Org:\t\t\t{self.org}\n"
            f"ASN:\t\t\t{repr(self.asn)}"
        )
