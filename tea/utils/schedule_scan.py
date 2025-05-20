"""Handles the scheduling of scans based on a configuration file."""

import json
import logging

from tea import scan

logger = logging.getLogger(__name__)


def schedule_scan(config_path: str):
    """
    Perform a scheduled scan based on the provided configuration file.

    :param config_path: Path to the configuration file.
    :type config_path: str
    """
    try:
        with open(config_path, encoding="utf-8") as file:
            config = json.load(file)

    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        return

    scan_type = config.get("scan_type", "full")
    domain = config.get("domain")
    country_codes = config.get("country_codes", [])
    use_existing = config.get("use_existing", False)
    save = config.get("save", True)

    if scan_type == "full":
        if not domain and not use_existing:
            logger.error("Domain or use_existing is required for full scan.")
            return

        scan.full(
            domain=domain,
            country_codes=country_codes,
            use_existing=use_existing,
            save=save,
        )

    elif scan_type == "discovery" and domain:
        if not domain:
            logger.error("Domain is required for discovery scan.")
            return

        scan.discovery(
            domain=domain,
            country_codes=country_codes,
            save=save,
        )

    else:
        logger.error(f"Unknown scan type: {scan_type}")
        raise ValueError(f"Invalid scan type: {scan_type}")

    logger.debug(f"Scan type {scan_type} for domain {domain} completed silently.")
