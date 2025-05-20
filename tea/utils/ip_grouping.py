"""Utility function that groups IP addresses into subnets."""

from collections import OrderedDict, defaultdict
from ipaddress import IPv4Network

from tea import models


def group_ips(
    target_hosts: list[models.TargetHost], subnet_mask: int = 20
) -> dict[IPv4Network, int]:
    """
    Group target host IPs into subnets based on the given subnet mask.

    :param target_hosts: List of TargetHost objects to group IPs for.
    :type target_hosts: list[models.TargetHost]
    :param subnet_mask: Subnet mask to use for grouping. Default is 20.
    :type subnet_mask: int
    :return: Dictionary grouped by subnet with the related IP count. Sorted by IP count.
    :rtype: dict[IPv4Network, int]
    """
    # Dictionary with subnet as key and IP count as value
    subnets_counts: dict[IPv4Network, int] = defaultdict(int)

    # Iterate over each target and group into subnets
    for target in target_hosts:
        network = IPv4Network((target.ip, subnet_mask), strict=False)
        subnets_counts[network] += 1

    # Sort the dictionary by IP count in descending order
    subnets_counts = OrderedDict(
        sorted(subnets_counts.items(), key=lambda item: item[1], reverse=True)
    )

    return subnets_counts
