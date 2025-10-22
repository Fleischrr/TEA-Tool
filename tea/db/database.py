"""Database module for managing SQLite database connections and operations."""

import logging
import os
import sqlite3
from pathlib import Path

from dotenv import get_key

from tea import models
from tea.db import insert, schema

logger = logging.getLogger(__name__)

TEA_ROOT = Path(os.getenv("TEA_ROOT", os.getcwd())) 


def get_connection(check: bool = False) -> sqlite3.Connection | None:
    """
    Create a connection to the SQLite database.

    :param check: Check only, does not create tables, defaults to False
    :type check: bool, optional
    :return: Returns the SQLite connection object or None if check is True and no tables exist.
    :rtype: sqlite3.Connection | None
    """
    db_path = str(get_key(dotenv_path=TEA_ROOT / ".env", key_to_get="EXPOSURE_DB_PATH"))

    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        cursor = conn.cursor()

        # Check if the database file exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()

        if not tables:
            logger.debug("No tables found.")

            if check:
                logger.debug("DB check enabled, do not create tables.")
                return None

            logger.debug("Creating database tables.")
            schema.create_all_tables(cursor)

            # Get number of list created
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            logger.debug(f"Created {len(cursor.fetchall())} tables.")

        cursor.close()
        return conn

    except sqlite3.OperationalError as e:
        logger.error(f"Error connecting to database: {e}")
        raise


# noinspection PyInconsistentReturns,PyTypeChecker
def execute_sql(sql: str, rows: list[tuple]) -> bool:
    """
    Commit one or multiple SQL queries into the database.

    :param sql: The SQL query to execute.
    :param rows: The data related to the SQL query.
    :return: True if the commit was successful, False otherwise.
    :rtype: bool
    """
    conn = get_connection()

    row: tuple | None = None
    if len(rows) == 1:
        row = rows[0]

    if conn:
        try:
            cursor = conn.cursor()

            if row is not None:
                cursor.execute(sql, row)
                conn.commit()
                return cursor.rowcount == 1
            else:
                cursor.executemany(sql, rows)
                conn.commit()
                return cursor.rowcount == len(rows)

        except sqlite3.IntegrityError as e:
            logger.error(f"Database insert failed: {e}")
            return False

        finally:
            conn.close()
    
    return True


def save_discovery(exposure: list[models.TargetHost]) -> bool:
    """
    Insert or update the exposure data into the database.

    This includes basic TargetHost information, related hostnames and ASN information.

    :param exposure: The TargetHost objects to store.
    :type exposure: list[models.TargetHost]
    :return: True if the inserts were successful, False otherwise.
    :rtype: bool
    """
    host_count: int = 0
    asn_count: int = 0
    hostnames_count: int = 0

    for host in exposure:
        # Insert ASN and count if exists and successful
        if host.asn and insert.asn(host):
            asn_count += 1

        # Insert host and count if successful
        if insert.target_host(host):
            host_count += 1

        # Insert hostnames and count if exists and successful
        if host.hostnames and insert.hostnames(host):
            hostnames_count += 1

    if host_count != len(exposure):
        print(
            f"   | Failed to insert complete Discovery Scan. "
            f"List length: {len(exposure)} and Host count: {host_count} are not equal. "
            f"Attempted to insert {asn_count} ASNs and {hostnames_count} hostnames.\n"
            f" --- Discovery Scan results not saved to database."
        )
        return False
    else:
        print(
            f"   | Successfully inserted/updated {asn_count} ASN and "
            f"{hostnames_count} hostname information for {host_count} host(s).\n"
            f" --- Discovery Scan results saved to database."
        )
        return True


def save_full(exposure: list[models.TargetHost]) -> bool:
    """
    Insert or update the full exposure data into the database.

    Stores an initial Discovery Scan before retrieving and
    storing detailed port information into the database.

    :param exposure: The TargetHost objects to store.
    :type exposure: list[models.TargetHost]
    :return: True if the inserts were successful, False otherwise.
    :rtype: bool
    """
    total_ports: int = 0
    port_count: int = 0
    vuln_count: int = 0
    opt_count: int = 0

    # Perform an initial discovery scan
    save_discovery(exposure)

    conn = get_connection()
    if conn:
        cursor = conn.cursor()

        for host in exposure:
            # Insert port and count if successful
            if insert.ports(host):
                port_count += 1

            # Retrieve port db info and map port numbers to port IDs
            cursor.execute("SELECT id, number from port WHERE ip_address = ?", (str(host.ip),))
            port_results = {port[1]: port[0] for port in cursor.fetchall()}

            hostnames_to_update: list[tuple] = []
            for port in host.ports:
                total_ports += 1
                port_id = port_results.get(port.number)

                # Insert and count both vulns and opts if they exist and successful
                if port.vulns and insert.vulns(port_id, port):
                    vuln_count += 1

                if port.opts and insert.opts(port_id, port):
                    opt_count += 1

                for name in port.hostnames:
                    hostnames_to_update.append(
                        (
                            port_id,
                            name,
                            str(host.ip),
                        )
                    )

            if hostnames_to_update:
                execute_sql(
                    "UPDATE hostname SET port_id = ? WHERE name = ? AND ip_address = ?",
                    hostnames_to_update,
                )

        conn.close()

    if port_count != len(exposure):
        print(
            f"  | Failed to insert complete Full Scan. Total host(s): "
            f"{len(exposure)} and host(s) with inserted ports: {port_count} are not equal.\n"
            f" -- Full Scan results not saved to database."
        )
        return False
    else:
        print(
            f"  | Successfully inserted {vuln_count} vuln(s), "
            f"{opt_count} opt(s) and {port_count} port(s) "
            f"from {total_ports} port(s) and {len(exposure)} host(s).\n"
            f" -- Full Scan results saved to database."
        )
        return True
