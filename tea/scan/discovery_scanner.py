"""Provides a Discovery scanner that retrieves subdomains and ASN information."""

import logging
from ipaddress import IPv4Network

from tea import db, models, scan, utils
from tea.models.asn import ASN

logger = logging.getLogger(__name__)


def asn_lookup(
    exposure: list[models.TargetHost],
) -> tuple[dict[IPv4Network, ASN], set[IPv4Network]]:
    """
    Perform an ASN lookup for a list of TargetHost objects (exposure).

    This function groups the hosts by their IP address into subnets and
    performs an ASN lookup for each subnet using the HackerTarget API.
    Duplicate ASN entries are merged into a single ASN object.

    :param exposure: A list of TargetHost objects to perform ASN lookup on.
    :type exposure: list[models.TargetHost]
    :return: A dictionary with subnets as keys and ASN objects as values.
    :rtype: dict[IPv4Network, ASN]
    """
    print(f"`--- ASN scan started for {len(exposure)} hosts...")

    # Group hosts by IP address into subnets
    subnets = utils.group_ips(exposure, subnet_mask=24)
    failed_subnets: set[IPv4Network] = set()

    if len(subnets) > 10:
        logger.warning(
            f"Subnet grouping count is {len(subnets)}, "
            f"might be too large for default HackerTarget API limit (20/day). "
            f"Some features may be limited."
        )

    # ASN lookup for each IP grouping/subnet
    asn_results: dict[IPv4Network, ASN] = {}

    for subnet in subnets:
        representative_ip = subnet.network_address

        try:
            tmp_host = models.TargetHost(ip=representative_ip)
            scan.asn(tmp_host)

            # ASN scan fails
            if tmp_host.asn is None:
                logger.warning(f"ASN Scan failed for {representative_ip}")
                failed_subnets.add(subnet)
                continue

            # Check if ASN is already in the results
            existing_asn = next(
                (asn for asn in asn_results.values() if asn.number == tmp_host.asn.number), None
            )

            if existing_asn:
                existing_asn.add_subnet(subnet)
                logger.debug(f"Appended subnet {subnet} to existing AS{existing_asn.number}")
            else:
                asn_results[subnet] = tmp_host.asn
                logger.debug(f"Subnet {subnet} has AS{tmp_host.asn.number}")

        except Exception as e:
            logger.warning(f"ASN scan failed for {subnet}: {e}")
            continue

    return asn_results, failed_subnets


def assign_asn(
    exposure: list[models.TargetHost],
    asn_results: dict[IPv4Network, ASN],
    failed_subnets: set[IPv4Network],
) -> None:
    """
    Assign ASN information to a list of TargetHost objects (exposure).

    This function checks if the host IP is already in a known ASN subnet
    and applies the ASN information to the host.
    If not, it performs a new ASN lookup and assigns the new ASN
    information to the host.

    :param exposure: A list of TargetHost objects to assign ASN information to.
    :param asn_results: A dictionary of ASN results with subnets as keys and ASN objects as values.
    """
    unique_asn: set[str] = set()

    for target_host in exposure:
        assigned = False

        # For each ASN result check if host is in that subnet
        for _subnet, asn in asn_results.items():
            if not asn or not asn.subnets:
                continue

            if any(target_host.ip in asn_subnet for asn_subnet in asn.subnets):
                target_host.asn = asn
                unique_asn.add(target_host.asn.number)
                assigned = True
                break

        # If not in known ASN subnet, perform a new ASN lookup
        if not assigned:
            # Skip if subnet failed ASN scan
            host_subnet = IPv4Network((target_host.ip, 24), strict=False)
            if host_subnet in failed_subnets:
                logger.debug(
                    f"Skipping fallback ASN lookup for {target_host.ip} (subnet already failed)"
                )
                continue

            try:
                scan.asn(target_host)

                if (
                    target_host.asn
                    and target_host.asn.number in [asn.number for asn in asn_results.values()]
                    and target_host.asn.subnets
                ):
                    matching_asn = next(
                        asn for asn in asn_results.values() if asn.number == target_host.asn.number
                    )
                    matching_asn.add_subnet(target_host.asn.subnets[0])
                    target_host.asn = matching_asn
                    logger.debug(f"Host {target_host.ip} matches existing AS{matching_asn.number}")

                elif target_host.asn:
                    asn_results[target_host.asn.subnets[0]] = target_host.asn
                    logger.debug(f"Found new AS{target_host.asn.number} from {target_host.ip}")

                unique_asn.add(target_host.asn.number)  # type: ignore
                assigned = True

            except Exception as e:
                logger.warning(f"ASN scan failed for {target_host.ip}: {e}")
                continue

        if not assigned:
            logger.debug(f"Host {target_host.ip} has no ASN assigned.")

    print(
        f"   | Found {len(unique_asn)} ASN(s) from {len(exposure)} hosts.\n --- ASN Scan completed."
    )


def discovery(
    domain: str, country_codes: list[str] | None = None, save: bool = True
) -> list[models.TargetHost] | None:
    """
    Perform a discovery scan on the given domain.

    :param domain: The domain to scan
    :type domain: str
    :param country_codes: A list of country codes to filter the results (optional).
    :type country_codes: list[str] | None
    :param save: Whether to save the discovered hosts to the database (default: True).
    :type save: bool
    :return: A list of TargetHost objects representing discovered hosts.
    :rtype: list[models.TargetHost] | None
    """
    try:
        print(f"`-- Starting Discovery Scan for domain: {domain}")

        # Retrieve subdomains from the domain name
        if country_codes is not None:
            target_hosts = scan.domain(domain, country_codes)
        else:
            target_hosts = scan.domain(domain)

        if not target_hosts:
            logger.warning(f"No hosts discovered for {domain}")
            return None

        # Perform ASN lookup and assign information for each host
        asn_results, failed_subnets = asn_lookup(target_hosts)
        assign_asn(target_hosts, asn_results, failed_subnets)

        if save:
            print("`--- Saving results to database...")
            db.save_discovery(target_hosts)

        print(f" -- Discovery Scan completed for {domain}.")

        return target_hosts

    except Exception as e:
        logger.error(f"Discovery scan failed for {domain}: {e}")
        raise
