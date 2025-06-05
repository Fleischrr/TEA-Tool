"""Provides an IP scanner that retrieves IP and detailed port information."""

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
    TargetHost object in place. Runs the free scan if API key is not sufficiant.

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
        logger.error(f"Error during SHODAN API search for {target.ip}: {e}")
        raise


def shodan_free_scan(target: models.TargetHost) -> None:
    """
    Retrieve basic information from the free SHODAN API.

    Populates the TargetHost with basic information such as open ports,
    hostnames, and vulnerabilities. Modifies the given TargetHost object in place.

    :param target: The target host to scan.
    :type target: models.TargetHost
    :raises requests.exceptions.RequestException: If the InternetDB request fails.
    """
    url = f"https://internetdb.shodan.io/{target.ip}"

    try:
        response: requests.Response = requests.get(url, timeout=10)

        if response.status_code == 404:
            logger.warning(f"No data found for {target.ip} in InternetDB.")
            return

        response.raise_for_status()
        ip_info = response.json()

        # Populate hostnames
        hostnames = ip_info.get("hostnames", [])
        target.add_hostnames(utils.validate_subdomain(hostnames))

        # Ports
        ports = ip_info.get("ports", [])
        target.add_ports(ports)

        # Vulns
        # If a vuln exist on a port, all other ports will display the same vuln.
        # TODO: Find a solution for this, ok as of now because its free.
        vulns = ip_info.get("vulns", [])
        port_vulns = [models.PortVuln(name=vuln) for vuln in vulns]

        for port in target.ports:
            port.vulns = port_vulns

    except requests.exceptions.RequestException as e:
        print(f"   | Error during SHODAN db search: {e}")
        logger.error(f"Error during SHODAN db search for {target.ip}: {e}")
        raise


def ip(target: models.TargetHost) -> None:
    """
    Perform an IP scan of a TargetHost by using the SHODAN API.

    :param target: The target host to scan.
    :type target: models.TargetHost
    """
    shodan_api = utils.get_shodan_api()

    try:
        if shodan_api is not None:
            shodan_paid_scan(shodan_api, target)

        else:
            raise ValueError("SHODAN API not configured.")

    except (shodan.APIError, ValueError) as e:
        if "403" in str(e) or isinstance(e, ValueError) or "No information available":
            logger.debug(f"Falling back to InternetDB API for {target.ip} (reason: {e})")
            shodan_free_scan(target)
        else:
            print(f"   | Error during SHODAN search: {e}")
            raise
