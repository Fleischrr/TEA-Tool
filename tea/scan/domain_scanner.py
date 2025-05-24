"""Provides a Domain scanner that retrieves subdomains and IPs using the SHODAN API."""

import logging
from ipaddress import IPv4Address, ip_address

import shodan
import requests
import tldextract

from tea import models, utils

logger = logging.getLogger(__name__)


def shodan_dns_records(
    shodan_api, domain_name: str, target_domains: dict[IPv4Address, models.TargetHost]
) -> dict[IPv4Address, models.TargetHost]:
    """
    Retrieve DNS records for a given domain using the SHODAN API.

    This function scans the DNS records for 'A' records associated with the
    specified domain name using the SHODAN API. It collects valid 'A' records
    and updates the target_domains dictionary with TargetHost objects for each
    unique IP address found.

    :param shodan_api: The SHODAN API object.
    :type shodan_api: shodan.Shodan
    :param domain_name: The domain name to scan (e.g., "example.com").
    :type domain_name: str
    :param target_domains: A dictionary mapping IP addresses (key) to TargetHost objects.
    :type target_domains: dict[IPv4Address, models.TargetHost]
    :return: A dictionary mapping IP addresses to TargetHost objects.
    :rtype: dict[IPv4Address, models.TargetHost]
    """
    # Use SHODAN to scan the domain DNS records
    shodan_result = shodan_api.dns.domain_info(domain_name)
    shodan_subdomains = shodan_result.get("subdomains", [])
    shodan_dns_rec = shodan_result.get("data", [])

    # Add valid 'A' records to target_domains
    for record in shodan_dns_rec:
        if (
                record.get("subdomain") in shodan_subdomains
                and record.get("value")
                and record.get("type") == "A"
        ):
            ip = IPv4Address(record.get("value"))
            subdomain_records = record.get("subdomain")
            hostnames = (
                utils.validate_subdomain([subdomain_records]) if subdomain_records else []
            )

            # Check for duplicate TargetHosts
            if ip not in target_domains:
                target_domains[ip] = models.TargetHost(ip)

            # Add subdomain info to the existing or new TargetHost
            target_host = target_domains[ip]
            target_host.domain = domain_name
            target_host.add_hostnames(hostnames)

    print(
        f"   | All 'A' records retrieved for {domain_name} "
        f" from {len(shodan_dns_rec)} DNS records (SHODAN)."
    )

    return target_domains


def hackertarget_dns_records(
    domain_name: str, target_domains: dict[IPv4Address, models.TargetHost]
) -> dict[IPv4Address, models.TargetHost] | None:
    """
    Retrieve DNS records for a given domain using the HackerTarget API.
    This function scans the DNS records for 'A' records associated with the
    specified domain name using the HackerTarget API. It collects valid 'A' records
    and updates the target_domains dictionary with TargetHost objects for each
    unique IP address found.

    :param domain_name: The domain name to scan (e.g., "example.com").
    :type domain_name: str
    :param target_domains: A dictionary mapping IP addresses (key) to TargetHost objects.
    :type target_domains: dict[IPv4Address, models.TargetHost]
    :return: A dictionary mapping IP addresses to TargetHost objects.
    :rtype: dict[IPv4Address, models.TargetHost] | None
    """

    url = f"https://api.hackertarget.com/hostsearch/?q={domain_name}"

    try:
        response: requests.Response = requests.get(url, timeout=10)
        response.raise_for_status()
        lines = response.text.splitlines()

        for line in lines:
            if ',' not in line:
                continue

            subdomain, ip_str = line.split(',', 1)

            try:
                ip = IPv4Address(ip_str)
            except ValueError:
                continue

            hostname = utils.validate_subdomain([subdomain])

            if ip not in target_domains:
                target_domains[ip] = models.TargetHost(ip)

            target_host = target_domains[ip]
            target_host.domain = domain_name
            target_host.add_hostnames(hostname)

        print(
            f"   | All 'A' records retrieved for {domain_name} "
            f" from {len(lines)} DNS records (HackerTarget)."
        )

        return target_domains

    except requests.exceptions.RequestException:
        print(
            "   | Error during HackerTarget DNS records retrieval. "
            "Please check your internet connection or the HackerTarget API."
        )
        logger.warning("Error during HackerTarget DNS records retrieval.")

        raise requests.exceptions.RequestException


def shodan_domain_search(
    shodan_api, query: str, target_domains: dict[IPv4Address, models.TargetHost], domain_name: str
) -> None:
    """
    Perform a SHODAN search for the given query and update target_domains.

    This function searches the SHODAN API for the specified query and updates
    the target_domains dictionary with the results. It adds subdomain names
    and IP addresses to the corresponding TargetHost objects.

    :param shodan_api: The SHODAN API object.
    :type shodan_api: shodan.Shodan
    :param query: The search query to use for the SHODAN API.
    :type query: str
    :param target_domains: A dictionary mapping IP addresses (key) to TargetHost objects.
    :type target_domains: dict[IPv4Address, models.TargetHost]
    :param domain_name: The domain name associated with the search.
    :type domain_name: str
    """
    try:
        search_result = shodan_api.search(query=query)
    except shodan.APIError as e:
        error_message = str(e)
        if "Access denied (403 Forbidden)" in error_message:
            print(
                "   | Free SHODAN API cannot use domain/search functionality. "
                "Upgrade your API key to retrieve broader results "
                "with SHODAN."
            )
        else:
            print(f"   | Error during SHODAN search: {error_message}")

        logger.warning(f"Error during SHODAN search: {error_message}")
        return

    search_matches = search_result.get("matches", [])

    for match in search_matches:
        try:
            # Skip if "ip_str" is not IPv4 or malformed
            ip = ip_address(match.get("ip_str"))
            if not isinstance(ip, IPv4Address):
                logger.debug(f"Skipping non-IPv4 address: {ip}")
                continue
            tmp_hostnames: list[str] = match.get("hostnames", [])
        except ValueError:
            logger.debug(f"Skipping malformed IP address: {match.get('ip_str')}")
            continue

        # Add subdomain info to the target_domains dictionary
        hostnames = utils.validate_subdomain(tmp_hostnames)

        # Check for duplicate TargetHosts
        if ip not in target_domains:
            target_domains[ip] = models.TargetHost(ip)

        # Add subdomain info to the existing or new TargetHost
        target_host = target_domains[ip]
        target_host.domain = domain_name
        target_host.add_hostnames(hostnames)

    print(
        f"   | All results retrieved from SHODAN search for query: {query}. "
        f"Received {len(search_matches)} matches."
    )


def domain(domain_name: str, country_codes: list[str] = None) -> list[models.TargetHost] | None:
    """
    Perform a domain scan using the SHODAN API.

    This function retrieves subdomains and their associated IP addresses by scanning
    the domain DNS records for 'A' records and retrieving these.
    Performs also a filtered search for the domain name in the SHODAN API and correlates the results
    with the subdomains found in the DNS 'A' records.
    Can also search for the domain name without suffix
    and filter by country code(s) (NO, UK, DE etc.).

    :param domain_name: The domain name to scan (e.g., "example.com").
    :type domain_name: str
    :param country_codes: A list of country codes to filter the search results (optional).
    :type country_codes: list[str]
    :return: A list of TargetHost objects for each IP address with each subdomain.
    :rtype: list[models.TargetHost] | None
    :raises shodan.APIError: If there is an error with the SHODAN API.
    """
    print(f"`--- Domain Scan started for: {domain_name}")

    # Validate the given domain name
    if not utils.validate_domain(domain_name):
        logger.error(f"Invalid domain name: {domain_name}")
        raise ValueError(f"Invalid domain name: {domain_name}")

    # Initialize SHODAN API
    shodan_api = utils.get_shodan_api()

    # Group TargetHost objects by IP address
    target_domains: dict[IPv4Address, models.TargetHost] = {}

    try:
        target_domains = shodan_dns_records(shodan_api, domain_name, target_domains)

    except shodan.APIError as e:
        error_message = str(e)
        if "Access denied (403 Forbidden)" in error_message:
            print(
                "   | Free SHODAN API cannot use domain/search functionality. "
                "Upgrade your API key to retrieve broader results. "
                "with SHODAN."
            )

            target_domains = hackertarget_dns_records(domain_name, target_domains)


        else:
            print(f"   | Error during SHODAN search: {error_message}")
            logger.warning(f"Error during SHODAN search: {error_message}")
            raise error_message


    # Use SHODAN to search for the domain in the search API
    domain_search_query = f"hostname:{domain_name}"
    shodan_domain_search(
        shodan_api,
        query=domain_search_query,
        target_domains=target_domains,
        domain_name=domain_name,
    )

    # Search for domain name w/o suffix but with country code(s)
    if country_codes:
        extracted_name = tldextract.extract(domain_name).domain

        if len(country_codes) == 1:
            country_search_query = f"{extracted_name} country:{country_codes[0]}"
        else:
            country_search_query = f"{extracted_name} country:{','.join(country_codes)}"

        shodan_domain_search(
            shodan_api,
            query=country_search_query,
            target_domains=target_domains,
            domain_name=domain_name,
        )

    # Create and sort a list[TargetHost] from the scan results
    target_hosts: list[models.TargetHost] = list(target_domains.values())
    target_hosts = sorted(target_hosts, key=lambda host: host.ip)

    print(
        f"   | Found {len(target_hosts)} hosts from {domain_name}\n --- Domain Scan completed."
    )

    return target_hosts

