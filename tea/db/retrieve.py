"""Insert functions for the database."""

import logging
from ipaddress import IPv4Address, IPv4Network

from tea import db, models
from tea.models.asn import ASN
from tea.models.port import Port

logger = logging.getLogger(__name__)


def target_hosts(ip_addresses: list[IPv4Address] | None = None) -> list[models.TargetHost]:
    """
    Retrieve TargetHost object(s) from the database.

    This function retrieves all target hosts from the database by default.
    If a list of IP address is provided, it retrieves those specific target hosts.

    :param ip_addresses: An optional list of IP addresses to retrieve from the database.
    :type ip_addresses: list[IPv4Address] | None
    :return: A list of TargetHost objects (exposure).
    :rtype: list[models.TargetHost]
    """
    exposure: list[models.TargetHost] = []
    conn = db.get_connection()
    cursor = conn.cursor()

    if not ip_addresses:
        cursor.execute("SELECT ip_address FROM target_host")
        ip_addresses = [row[0] for row in cursor.fetchall()]

    # Get all IP addresses from the database
    logger.debug(f"Retrieved {len(ip_addresses)} IP address(es) from the database.")

    # Retrieve Exposure
    host_sql = """
    SELECT ip_address, operating_system, domain, organization, asn, created_at, modified_at
    FROM target_host
    WHERE ip_address = ?
    """

    for ip in ip_addresses:
        cursor.execute(host_sql, (ip,))
        host = cursor.fetchone()

        # Create TargetHost and append to exposure list
        if host:
            target_host = models.TargetHost(IPv4Address(host[0]))
            target_host.os = host[1]
            target_host.domain = host[2]
            target_host.org = host[3]
            target_host.asn = ASN(host[4]) if host[4] else None
            target_host.created_at = host[5]
            target_host.modified_at = host[6]

            exposure.append(target_host)

    return exposure


def asn(exposure: list[models.TargetHost]) -> bool:
    """
    Retrieve ASN information for each TargetHost in the exposure list.

    This function retrieves ASN information from the database and
    associates it with the corresponding TargetHost objects.

    :param exposure: The list of TargetHost objects to update with ASN information.
    :type exposure: list[models.TargetHost]
    :return: True if the retrieval was successful, False otherwise.
    :rtype: bool
    """
    conn = db.get_connection()
    cursor = conn.cursor()

    # Retrieve all ASNs from database
    cursor.execute("""
    SELECT number, name, description, created_at, modified_at
    FROM asn
    """)
    asn_results = cursor.fetchall()
    logger.debug(f"Retrieved {len(asn_results)} ASN(s) from the database.")
    asn_map: dict[str, ASN] = {}

    for asn_result in asn_results:
        asn_obj = ASN(
            number=asn_result[0],
            name=asn_result[1],
            description=asn_result[2],
            created_at=asn_result[3],
            modified_at=asn_result[4],
        )

        # Retrieve subnets for ASN
        cursor.execute("SELECT subnet FROM asn_subnet WHERE asn_number = ?", (asn_obj.number,))
        subnets = [IPv4Network(row[0]) for row in cursor.fetchall()]
        logger.debug(f"Retrieved {len(subnets)} subnet(s) for AS{asn_obj.number}.")
        asn_obj.subnets = subnets

        # Map ASN number to ASN object
        asn_map[asn_obj.number] = asn_obj

    for host in exposure:
        if host.asn and host.asn.number in asn_map:
            host.asn = asn_map[host.asn.number]

    logger.debug(f"Retrieved ASN information for {len(exposure)} host(s).")

    conn.close()
    return True


def hostnames(exposure: list[models.TargetHost]) -> bool:
    """
    Retrieve hostnames for each TargetHost in the exposure list.

    This function retrieves hostnames from the database and
    associates them with the corresponding TargetHost objects.

    :param exposure: The list of TargetHost objects to update with hostname information.
    :type exposure: list[models.TargetHost]
    :return: True if the retrieval was successful, False otherwise.
    :rtype: bool
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    hostname_sql = "SELECT name FROM hostname WHERE ip_address = ?"

    for host in exposure:
        cursor.execute(hostname_sql, (str(host.ip),))
        host.hostnames = [row[0] for row in cursor.fetchall()]

        if len(host.ports) > 0:
            # Map port_id to hostnames
            cursor.execute(
                "SELECT port_id, name FROM hostname WHERE ip_address = ? AND port_id IS NOT NULL",
                (str(host.ip),),
            )

            hostname_map: dict[int | None, list[str]] = {}
            for port_id, name in cursor.fetchall():
                if port_id not in hostname_map:
                    hostname_map[port_id] = []
                hostname_map[port_id].append(name)

            # Apply hostnames to associated port_id
            for port in host.ports:
                cursor.execute(
                    "SELECT id FROM port WHERE ip_address = ? AND number = ?",
                    (str(host.ip), port.number),
                )
                port_result = cursor.fetchone()

                if port_result:
                    port_id = port_result[0]

                    if port_id in hostname_map:
                        port.hostnames = hostname_map[port_id]

    logger.debug(f"Retrieved hostname information for {len(exposure)} host(s).")

    conn.close()
    return True


def ports(exposure: list[models.TargetHost]) -> bool:
    """
    Retrieve ports for each TargetHost in the exposure list.

    This function retrieves ports from the database and
    associates them with the corresponding TargetHost objects.

    :param exposure: The list of TargetHost objects to update with port information.
    :type exposure: list[models.TargetHost]
    :return: True if the retrieval was successful, False otherwise.
    :rtype: bool
    """
    conn = db.get_connection()
    cursor = conn.cursor()
    port_sql = """
    SELECT number, protocol, service, banner, http_status, created_at, modified_at, id
    FROM port WHERE ip_address = ?
    """

    for host in exposure:
        cursor.execute(port_sql, (str(host.ip),))
        port_results = cursor.fetchall()
        for row in port_results:
            port = Port(
                number=row[0],
                protocol=row[1],
                service=row[2],
                banner=row[3],
                http_status=row[4],
                created_at=row[5],
                modified_at=row[6],
            )
            host.ports.append(port)

            # Retrieve vulns and opts for this port
            port_id: int = row[7]
            cursor.execute(
                """
                SELECT name, created_at, modified_at 
                FROM port_vuln WHERE port_id = ?""",
                (port_id,),
            )
            port.vulns = [models.PortVuln(row[0], row[1], row[2]) for row in cursor.fetchall()]

            cursor.execute(
                """
                SELECT name, description, created_at, modified_at 
                FROM port_opt WHERE port_id = ?""",
                (port_id,),
            )
            port.opts = [
                models.PortOptional(row[0], row[1], row[2], row[3]) for row in cursor.fetchall()
            ]

    logger.debug(f"Retrieved port information for {len(exposure)} host(s).")

    conn.close()
    return True


def retrieve_exposure(ip_addresses: list[IPv4Address] | None = None) -> list[models.TargetHost]:
    """
    Retrieve exposure from the database.

    This function retrieves all target hosts by default,
    or a specific list of IP addresses if provided.

    :param ip_addresses: An optional list of IP addresses to retrieve from the database.
    :type ip_addresses: list[IPv4Address] | None
    :return: A list of TargetHost objects (exposure).
    :rtype: list[models.TargetHost]
    """
    hosts = target_hosts(ip_addresses)
    asn(hosts)
    ports(hosts)
    hostnames(hosts)

    return hosts
