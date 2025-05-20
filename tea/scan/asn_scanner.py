"""Provides an ASN scanner that retrieves ASN information using the HackerTarget API."""

import json
import logging
from ipaddress import IPv4Network

import requests

from tea import models
from tea.models.asn import ASN

logger = logging.getLogger(__name__)


def asn(target: models.TargetHost) -> None:
    """
    Perform an ASN lookup of the given TargetHost using the HackerTarget API.

    Populates the TargetHost with ASN information such as ASN number,
    name, subnet and description.

    :param target: The target host to scan.
    :type target: models.TargetHost
    :raises requests.exceptions.RequestException: If error with the HackerTarget API.
    """
    try:
        # Receive ASN data from given TargetHost.  TODO: Make API key a config option
        url: str = f"https://api.hackertarget.com/aslookup/?q={target.ip}&output=json&details=true"
        response: requests.Response = requests.get(url)
        response.raise_for_status()
        ip_data = json.loads(response.text)

        target.asn = ASN(
            number=ip_data.get("asn"),
            name=ip_data.get("asn_name"),
            description=ip_data.get("description"),
        )

        target.asn.add_subnet(IPv4Network(ip_data.get("asn_range")))

        # TODO: Make API key a config option
        # Retrieve additional subnets if not ISP or larger (20 or more subnets).
        subnet_url: str = f"https://api.hackertarget.com/aslookup/?q={target.asn.number}&output=json&details=true&subnets=true"
        subnet_response: requests.Response = requests.get(subnet_url)
        subnet_response.raise_for_status()
        subnet_data = json.loads(subnet_response.text)

        asn_subnets: list[IPv4Network] = subnet_data.get("prefixes", [])
        if len(asn_subnets) < 50:  # TODO: Make this a config option
            for subnet in asn_subnets:
                try:
                    target.asn.add_subnet(IPv4Network(subnet))
                except ValueError:
                    logger.debug(f"Skipping non IPv4 subnet: {subnet}")
                    continue
            logger.debug(
                f"Retrieved ASN data for {target.ip}: "
                f"AS{target.asn.number} with {len(asn_subnets)} subnets."
            )
        else:
            logger.debug(
                f"AS{target.asn.number} has too many subnets ({len(asn_subnets)}) to process."
            )

    except requests.exceptions.RequestException as e:
        print(f"[!] HackerTarget API request failed: {e}")
        logger.error(f"HackerTarget API request failed: {e}")
