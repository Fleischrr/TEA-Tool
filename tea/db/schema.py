"""Database schemas for the TEA-Tool."""

import sqlite3


def create_target_host_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the TargetHost table in th TEA database.

    :param cursor: SQLite cursor object
    :type cursor: sqlite3.Cursor
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS target_host (
            ip_address TEXT NOT NULL,
            operating_system TEXT,
            domain TEXT,
            organization TEXT,
            asn TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY (ip_address),
            FOREIGN KEY (asn) REFERENCES asn(number) ON DELETE SET NULL 
        );
    """)


def create_asn_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the ASN table in the TEA database.

    :param cursor: SQLite cursor object
    :type cursor: sqlite3.Cursor
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asn (
            number TEXT NOT NULL,
            name TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY (number)
        );
    """)


def create_asn_subnet_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the ASN Subnet table in the TEA database.

    :param cursor: SQLite cursor object
    :type cursor: sqlite3.Cursor
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS asn_subnet (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asn_number TEXT NOT NULL,
            subnet TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (asn_number, subnet),
            FOREIGN KEY (asn_number) REFERENCES asn(number) ON DELETE CASCADE ON UPDATE CASCADE
        );
    """)


def create_hostname_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the Hostname table in the TEA database.

    :param cursor: SQLite cursor object
    :type cursor: sqlite3.Cursor
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hostname (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            port_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (name, ip_address),
            FOREIGN KEY (ip_address) REFERENCES target_host(ip_address) ON DELETE CASCADE,
            FOREIGN KEY (port_id) REFERENCES port(id) ON DELETE CASCADE
        );
    """)


def create_port_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the Port table in the TEA database.

    :param cursor: SQLite cursor object
    :type cursor: sqlite3.Cursor
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            number INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            protocol TEXT,
            service TEXT,
            banner TEXT,
            http_status INTEGER CHECK (http_status BETWEEN 100 AND 599),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
            UNIQUE (number, ip_address),
            FOREIGN KEY (ip_address) REFERENCES target_host(ip_address) ON DELETE CASCADE
        );
    """)


def create_port_vuln_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the Port Vulnerability table in the TEA database.

    :param cursor: SQLite cursor object
    :type cursor: sqlite3.Cursor
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_vuln (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            port_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (name, port_id),
            FOREIGN KEY (port_id) REFERENCES port(id) ON DELETE CASCADE
        );
    """)


def create_port_opt_table(cursor: sqlite3.Cursor) -> None:
    """
    Create the Port Optional table in the TEA database.

    :param cursor: SQLite cursor object
    :type cursor: sqlite3.Cursor
    """
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS port_opt (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            port_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (name, port_id),
            FOREIGN KEY (port_id) REFERENCES port(id) ON DELETE CASCADE
        );
    """)


def create_all_tables(cursor: sqlite3.Cursor) -> None:
    """
    Create all tables in the TEA database.

    :param cursor: SQLite cursor object
    :type cursor: sqlite3.Cursor
    """
    create_target_host_table(cursor)
    create_port_table(cursor)
    create_asn_table(cursor)
    create_asn_subnet_table(cursor)
    create_hostname_table(cursor)
    create_port_vuln_table(cursor)
    create_port_opt_table(cursor)
