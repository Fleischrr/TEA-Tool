"""Handle CSV export of the exposure data."""

import csv
import re
from pathlib import Path

from tea import db, models

TEA_ROOT = Path(__file__).resolve().parent.parent


def export_to_csv(output_path: str | Path = (TEA_ROOT / "tea_exposure.csv")):
    """
    Export the exposure data to a CSV file.

    This function retrieves the exposure data from the database and writes it to a CSV file.
    Default stored in the TEA root directory as "tea_exposure.csv".

    :param output_path: The path where the CSV file will be saved.
    :type output_path: str | Path
    """
    exposure: list[models.TargetHost] = db.retrieve_exposure()
    if not exposure:
        print("No data to export.")
        return

    output_path = Path(output_path)

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        fieldnames = [
            "IP Address",
            "OS",
            "Domain",
            "Organization",
            "Hostnames",
            "Port Numbers",
            "Port Protocols",
            "Port Services",
            "Port Vulns",
            "Port Opts",
            "Banner",
            "HTTP Status",
            "ASN Number",
            "ASN Name",
            "ASN Description",
            "ASN Subnets",
        ]

        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        for host in exposure:
            port_numbers = []
            port_protocols = []
            port_services = []
            port_vulns = []
            port_opts = []
            port_http_status = []
            port_banners = []

            for port in host.ports:
                port_numbers.append(str(port.number))
                port_protocols.append(port.protocol or "-")
                port_services.append(port.service or "-")
                port_vulns.extend(port.vulns)
                port_opts.extend(port.opts)
                port_http_status.append(str(port.http_status) or "-")

                # Put the grabbed banner on one line
                if port.banner:
                    port_banners.append(re.sub(r"\s+", " ", port.banner.strip()))
                else:
                    port_banners.append("-")

            writer.writerow(
                {
                    "IP Address": str(host.ip),
                    "OS": host.os,
                    "Domain": host.domain,
                    "Organization": host.org,
                    "Hostnames": "; ".join(host.hostnames),
                    "Port Numbers": "; ".join(port_numbers),
                    "Port Protocols": "; ".join(port_protocols),
                    "Port Services": "; ".join(port_services),
                    "Port Vulns": "; ".join(vuln.name for vuln in port_vulns),
                    "Port Opts": "; ".join(str(opt) for opt in port_opts),
                    "Banner": "; ".join(port_banners),
                    "HTTP Status": "; ".join(port_http_status),
                    "ASN Number": host.asn.number if host.asn else "",
                    "ASN Name": host.asn.name if host.asn else "",
                    "ASN Description": host.asn.description if host.asn else "",
                    "ASN Subnets": "; ".join(str(s) for s in (host.asn.subnets or []))
                    if host.asn
                    else "",
                }
            )

    print(f"[+] CSV export completed: {output_path}")
