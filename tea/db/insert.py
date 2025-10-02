"""Insert functions for the database."""

from datetime import datetime

from tea import db, models
from tea.models.asn import ASN
from tea.models.port import Port


def target_host(host: models.TargetHost) -> bool:
    """
    Save a TargetHost object to the database.

    This function checks if the target host already exists in the database.
    If it does, it updates the existing entry. If it doesn't, it creates a new entry.

    :param host: The TargetHost object to save.
    :type host: TargetHost
    :return: True if the insert was successful, False otherwise.
    :rtype: bool
    """        
    # Insert or update target host
    host_sql = """
    INSERT INTO target_host(
        operating_system, domain, organization, asn, created_at, modified_at, ip_address
        )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (ip_address) DO UPDATE SET
        operating_system = excluded.operating_system,
        domain = excluded.domain,
        organization = excluded.organization,
        asn = excluded.asn,
        modified_at = excluded.modified_at
    """

    host_row: list[tuple] = [
        (
            host.os,
            host.domain,
            host.org,
            host.asn.number if host.asn else None,
            host.created_at,
            host.modified_at,
            str(host.ip),
        )
    ]

    return db.execute_sql(host_sql, host_row)


def asn(host: models.TargetHost) -> bool:
    """
    Save the ASN of a TargetHost object to the database.

    This function checks if the ASN already exists in the database.
    If it does, it updates the existing entry. If it doesn't, it creates a new entry.

    :param host: The TargetHost object whose ASN to save.
    :type host: TargetHost
    :return: True if insert was successful, False otherwise
    :rtype: bool
    """
    # Retrieve ASN from host, skip if none
    if not host.asn:
        return False
    
    asn = host.asn
    
    # Insert or update ASN
    asn_sql = """
    INSERT INTO asn(name, description, created_at, modified_at, number) 
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(number) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        modified_at = excluded.modified_at
    """
    
    asn_row: list[tuple] = [
        (
            asn.name,
            asn.description,
            asn.created_at,
            asn.modified_at,
            str(asn.number),
        )
    ]

    success = db.execute_sql(asn_sql, asn_row)

    if success and asn.subnets:
        return asn_subnets(asn)

    return success


def asn_subnets(host_asn: ASN) -> bool:
    """
    Save the ASN subnets of a TargetHost object to the database.

    This function checks if the ASN subnets already exist in the database.
    If they do, it updates the existing entries. If they don't, it creates new entries.

    :param host_asn: The ASN object whose subnets to save.
    :type host_asn: ASN
    :return: True if the insert was successful, False otherwise.
    :rtype: bool
    """
    # Insert or update ASN subnets
    subnet_sql = """
    INSERT INTO asn_subnet(asn_number, created_at, modified_at, subnet)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(asn_number, subnet) DO UPDATE SET 
        modified_at = excluded.modified_at
    """

    subnet_rows: list[tuple] = []
    for subnet in host_asn.subnets:
        subnet_rows.append(
            (
                str(host_asn.number),
                host_asn.created_at,
                host_asn.modified_at,
                str(subnet),
            )
        )

    return db.execute_sql(subnet_sql, subnet_rows)


def hostnames(host: models.TargetHost) -> bool:
    """
    Save the hostnames of a TargetHost object to the database.

    This function checks if the hostname already exists in the database.
    If it does, it updates the existing entry. If it doesn't, it creates a new entry.

    :param host: The TargetHost object whose hostnames to save.
    :type host: TargetHost
    :return: True if the insert was successful, False otherwise.
    :rtype: bool
    """
    # Skip if no hostnames on the host
    if not host.hostnames:
        return False

    # Insert or update hostnames
    hostname_sql = """
    INSERT INTO hostname(name, created_at, modified_at, ip_address)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(name, ip_address) DO UPDATE SET
        modified_at = excluded.modified_at
    """

    hostname_rows: list[tuple] = []
    for name in host.hostnames:
        hostname_rows.append(
            (
                name,
                host.created_at,
                host.modified_at,
                str(host.ip),
            )
        )

    return db.execute_sql(hostname_sql, hostname_rows)


def ports(host: models.TargetHost) -> bool:
    """
    Save the ports of a TargetHost object to the database.

    This function checks if the port already exists in the database.
    If it does, it updates the existing entry. If it doesn't, it creates a new entry.

    :param host: The TargetHost object whose ports to save.
    :type host: TargetHost
    :return: True if the insert was successful, False otherwise.
    :rtype: bool
    """
    # Skip if no ports on the host
    if not host.ports:
        return False

    # Insert or update ports
    port_sql = """
    INSERT INTO port(
        protocol, service, banner, http_status, number, created_at, modified_at, ip_address
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (number, ip_address) DO UPDATE SET
        protocol = excluded.protocol,
        service = excluded.service,
        banner = excluded.banner,
        http_status = excluded.http_status,
        modified_at = excluded.modified_at
    """

    port_rows: list[tuple] = []
    for port in host.ports:

        port_rows.append(
            (
                port.protocol,
                port.service,
                port.banner,
                port.http_status,
                port.number,
                port.created_at,
                port.modified_at,
                str(host.ip),
            )
        )

    return db.execute_sql(port_sql, port_rows)


def vulns(port_id: int, port: Port) -> bool:
    """
    Save the vulnerability(ies) of a Port object to the database.

    This function checks if the vuln(s) already exists in the database.
    If it does, it updates the existing entry. If it doesn't, it creates a new entry.

    :param port_id: The DB ID of the Port object whose vulnerabilities to save.
    :type port_id: int
    :param port: The Port object whose vulnerabilities to save.
    :type port: Port
    :return: True if the insert was successful, False otherwise.
    :rtype: bool
    """
    # Skip if no vulns on the port
    if not port.vulns:
        return False

    # Insert or update vulns
    vuln_sql = """
    INSERT INTO port_vuln(name, created_at, modified_at, port_id)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(name, port_id) DO UPDATE SET
        modified_at = excluded.modified_at
    """

    vuln_rows: list[tuple] = []
    for vuln in port.vulns:
        
        vuln_rows.append(
            (
                vuln.name,
                vuln.created_at,
                vuln.modified_at,
                port_id,
            )
        )

    return db.execute_sql(vuln_sql, vuln_rows)


def opts(port_id: int, port: Port) -> bool:
    """
    Save the optional information of a Port object to the database.

    This function checks if the opt(s) already exists in the database.
    If it does, it updates the existing entry. If it doesn't, it creates a new entry.

    :param port_id: The DB ID of the Port object whose opts to save.
    :type port_id: int
    :param port: The Port object whose opts to save.
    :type port: Port
    :return: True if the insert was successful, False otherwise.
    :rtype: bool
    """
    # Skip if no opts on the port
    if not port.opts:
        return False

    # Insert or update opts
    opt_sql = """
    INSERT INTO port_opt(name, description, created_at, modified_at, port_id)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(name, port_id) DO UPDATE SET
        modified_at = excluded.modified_at
    """

    opt_rows: list[tuple] = []
    for opt in port.opts:
        
        opt_rows.append(
            (
                opt.name,
                opt.description,
                opt.created_at,
                opt.modified_at,
                port_id,
            )
        )

    return db.execute_sql(opt_sql, opt_rows)
