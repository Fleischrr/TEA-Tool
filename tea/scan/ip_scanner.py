"""Provides an IP scanner that retrieves IP and detailed port information."""

import logging

import shodan

from tea import models, utils

logger = logging.getLogger(__name__)


def ip(target: models.TargetHost) -> None:
    """
    Perform an IP scan of a TargetHost by using the SHODAN API.

    Populates the TargetHost with information such as hostnames,
    Operative Systems, organization and more.
    Ports are also populated with detailed information including protocol,
    associated service, and vulnerabilities.

    :param target: The target host to scan.
    :type target: models.TargetHost
    :return: None. Modifies the given TargetHost object in place.
    :raises shodan.APIError: If there is an error with the SHODAN API.
    """
    shodan_api = utils.get_shodan_api()

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
        logger.warning(f"IP Scan failed for {target.ip}: {e}")
        return
