"""Provides an IP scanner that retrieves IP and detailed port information."""

import json
import logging

import requests
import shodan

from tea import models, utils

logger = logging.getLogger(__name__)


def shodan_paid_scan(shodan_api: shodan.Shodan, target: models.TargetHost) -> None:
    """
    Retrieve detailed information from the paid SHODAN API.

    Populates the TargetHost with information such as hostnames,
    Operative Systems, organization and more.
    Ports are also populated with detailed information including protocol,
    associated service, and vulnerabilities. Modifies the given
    TargetHost object in place.

    :param target: The target host to scan.
    :type target: models.TargetHost
    :raises shodan.APIError: If there is an error with the SHODAN API.
    """
    try:
        # Convert IPv4 to a string and retrieve IP-scan result
        scan_result = shodan_api.host(str(target.ip))

        # Fill target host with scan information
        target.add_ports(scan_result.get("ports", []))
        target.add_hostnames(utils.validate_subdomain(scan_result.get("hostnames", [])))
        target.os = scan_result.get("os", "")
        target.org = scan_result.get("org", "")

        # Extract detailed service/port information
        for service in scan_result.get("data", []):
            # Map port and related information to the correct port object
            current_port = service.get("port")
            for port in target.ports:
                if port.number == current_port:
                    current_port = port
                    break

            if isinstance(current_port, int):
                logger.warning(f"No match found for port {current_port}.")
                continue

            # Fill port object with detailed information
            current_port.protocol = service.get("transport")
            current_port.hostnames = utils.validate_subdomain(service.get("hostnames", []))
            current_port.service = service.get("product", "")
            current_port.banner = service.get("data", "")

            if service.get("http"):
                current_port.http_status = service.get("http", {}).get("status")

            # Save vulnerabilities and other related properties
            opts = service.get("opts", {})
            vulns = opts.pop("vulns", [])

            if isinstance(vulns, dict):
                # Handle vulns if score is attached in a dict
                vulns = list(vulns.keys())

            current_port.vulns = [models.PortVuln(name=vuln) for vuln in vulns]
            current_port.opts = [
                models.PortOptional(name, str(desc)) for name, desc in opts.items()
            ]

    except shodan.APIError as e:
        error_message = str(e)
        if "Access denied (403 Forbidden)" in error_message:
            print(
                "  | Free SHODAN API cannot retrieve detailed IP Scan results. "
                "Upgrade your API key to retrieve more detailed results "
                "with SHODAN."
            )
            logger.info("SHODAN Key is forbidden (403), utilizing free IP Scan")

            shodan_free_scan(target)
        else:
            print(f"   | Error during SHODAN search: {error_message}")
            logger.error(f"Error during SHODAN search for {target.ip}: {error_message}")
            raise


def shodan_free_scan(target: models.TargetHost) -> None:
    """
    Retrieve basic information from the free SHODAN API.

    Populates the TargetHost with information such as TODO: WRITE MORE
    Modifies the given TargetHost object in place.

    :param target: The target host to scan.
    :type target: models.TargetHost
    :raises shodan.APIError: If there is an error with the SHODAN API.
    """
    url = ""

    try:
        response: requests.Response = requests.get(url, timeout=10)
        response.raise_for_status()
        ip_info = json.loads(response.text)

    except requests.exceptions.RequestException:
        raise

    raise NotImplementedError


def ip(target: models.TargetHost) -> None:
    """
    Perform an IP scan of a TargetHost by using the SHODAN API.

    :param target: The target host to scan.
    :type target: models.TargetHost
    """
    shodan_api = utils.get_shodan_api()
    try:
        if shodan_api is None:
            shodan_free_scan(target)

        else:
            shodan_paid_scan(shodan_api, target)

    except Exception as e:
        print(e)
        return
