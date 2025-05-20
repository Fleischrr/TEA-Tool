"""ASN dataclass for storing Autonomous System Number (ASN) information."""

from dataclasses import dataclass
from ipaddress import IPv4Network


@dataclass
class ASN:
    """
    Represents an Autonomous System Number (ASN) and its associated metadata.

    :param number: The ASN as a string.
    :type number: str
    :param name: Optional human-readable name of the ASN.
    :type name: str
    :param subnets: Optional IPv4 subnet associated with the ASN.
    :type subnets: list[IPv4Network]
    :param description: Optional description of the ASN.
    :type description: str
    """

    number: str
    name: str = ""
    subnets: list[IPv4Network] = None
    description: str = ""
    created_at: str = ""
    modified_at: str = ""

    def add_subnet(self, subnet: IPv4Network):
        """
        Add a subnet to the ASN.

        :param subnet: The subnet to add.
        :type subnet: IPv4Network
        """
        if self.subnets is None:
            self.subnets = []

        if subnet not in self.subnets:
            self.subnets.append(subnet)
            self.subnets.sort()

    def __repr__(self) -> str:
        """
        Return a string representation of the ASN.

        :return: The ASN as a string.
        :rtype: str
        """
        return str(f"{self.number}")

    def __str__(self) -> str:
        """
        Return a formatted string representation of the ASN.

        :return: A formatted string representation of the ASN.
        :rtype: str
        """
        return (
            f"ASN:\t\t\t{self.number}\n"
            f"Name:\t\t\t{self.name}\n"
            f"Subnet:\t\t\t{self.subnets}\n"
            f"Description:\t{self.description}"
        )
