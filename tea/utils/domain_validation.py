"""Utility function that validates root domain names."""

import ipaddress
import logging

import tldextract

logger = logging.getLogger(__name__)


def validate_domain(domain_name: str) -> bool:
    """
    Validate that the given domain name is a valid root domain name.

    This function rejects: IP addresses, Subdomains,
    Domains without a valid suffix or otherwise malformed.

    :param domain_name: The domain name to validate (e.g., "example.com").
    :type domain_name: str
    :return: True if the domain name is valid, False otherwise.
    :rtype: bool
    """
    logger.debug(f"Validating the domain name: {domain_name}")

    # Reject if given domain_name is an IP address
    try:
        ipaddress.ip_address(domain_name)
        logger.warning(f"Domain name is an IP address: {domain_name}")
        return False
    except ValueError:
        pass

    # Extract the domain name information
    extracted_domain = tldextract.extract(domain_name)
    logger.debug(
        f"Extracted: Subdomain={extracted_domain.subdomain},"
        f"Domain={extracted_domain.domain},"
        f"Suffix={extracted_domain.suffix}"
    )

    # Reject if the domain name is a subdomain
    if extracted_domain.subdomain:
        logger.warning(f"Domain name is a subdomain: {extracted_domain}")
        return False

    # Reject if the domain name is malformed
    if not extracted_domain.suffix and not extracted_domain.domain:
        logger.warning(f"Invalid domain name: {extracted_domain}")
        return False

    if not extracted_domain.suffix:
        logger.warning(f"Domain name is missing suffix: {extracted_domain}")
        return False

    # Return true/false based on the content of the extracted subdomain
    logger.debug(f"Domain validated successfully: {extracted_domain}")
    return True


def validate_subdomain(subdomain_names: list[str]) -> list[str]:
    """
    Validate the given subdomain names.

    This function checks if the subdomain names are valid and
    extracts the hostname/subdomain part from them. It also handles
    cases where the subdomain name might be a root domain or malformed.

    :param subdomain_names: A list of subdomain names to validate.
    :type subdomain_names: list[str]
    :return: A list of validated hostnames names from subdomains.
    :rtype: list[str]
    """
    # List to store validated subdomain names
    hostnames: list[str] = []

    # Validate the subdomain name(s)
    for name in subdomain_names:
        name_extracted = tldextract.extract(name)

        match (
            bool(name_extracted.subdomain),
            bool(name_extracted.domain),
            bool(name_extracted.suffix),
        ):
            case (True, True, True):
                hostnames.append(name_extracted.subdomain)
            case (True, True, False):
                hostnames.append(name_extracted.subdomain)
            case (True, False, False):
                hostnames.append(name_extracted.subdomain)
            case (False, True, False):
                hostnames.append(name_extracted.domain)
            case (False, False, True):
                hostnames.append(name_extracted.suffix)
            case _:
                logger.debug(f"Domain name is a root domain: {name_extracted}")

    return hostnames
