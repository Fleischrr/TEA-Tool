"""Helper functions for the TEA Tool."""

import argparse
import logging
import os
from collections import OrderedDict, defaultdict
from ipaddress import IPv4Network
from pathlib import Path

from tea import models

logger = logging.getLogger(__name__)


def verify_file_path(file_path: str) -> bool:
    """
    Verify the given file path as writeable and accessable.

    :param path: The file path to verify
    :type path: str
    :return: The stauts of the verification
    :rtype: bool
    """
    try:
        path = Path(file_path).expanduser().resolve()
        folder = path.parent
        
        if not folder.is_dir():
            logger.warning("Log path parent is not an existing directory.")
            return False

        if not os.access(folder, os.W_OK):
            logger.warning("Log path parent is not writeable.")
            return False

        if path.is_dir():
            logger.warning("Log path must be a file.")
            return False
        
        return True
    
    except Exception as e:
        logger.error(f"Failed to verify given file path with error: {e}")
        return False
    

def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments for the TEA-Tool.

    This function sets up the argument parser and defines the
    command line arguments that can be used when running the TEA-Tool.

    :return: Parsed command line arguments.
    :rtype: argparse.Namespace
    """
    # Define the argument parser
    arg_parser = argparse.ArgumentParser(
        description=("The TEA-Tool.\nAn open-source Threat Exposure Analysis CLI Tool."),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Create a group for optional arguments
    group = arg_parser.add_argument_group(
        "Optional arguments", "Headless options to schedule scans or export data."
    )

    # Make a mutually exclusive group for schedule and export
    exclusive_group = group.add_mutually_exclusive_group()
    exclusive_group.add_argument(
        "-s",
        "--schedule",
        metavar="../path/to/config.json",
        help="Schedule configuration file path",
    )
    exclusive_group.add_argument(
        "-x",
        "--export",
        metavar="../path/to/output.csv",
        help="Path to exported TEA exposure data (CSV format)",
    )

    return arg_parser.parse_args()


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
