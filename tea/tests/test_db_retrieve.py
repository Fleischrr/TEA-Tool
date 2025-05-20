"""Test retrieval of TargetHosts from the database."""

import logging

import tea.db.retrieve as retrieve
from tea import db, models

logger = logging.getLogger(__name__)


def test_retrieve_target_host():
    """Assert retrieval of TargetHost from the database."""
    logger.debug("\n\nTESTING DB RETRIEVAL FUNCTIONALITY\n----------------------------------")

    # Check db connection
    conn = db.get_connection()
    assert conn is not None
    conn.close()

    # Assess TargetHost retrieval
    exposure: list[models.TargetHost] = retrieve.target_hosts()
    logger.debug(f"\n`->\tExposure count: {len(exposure)}")

    assert len(exposure) > 0

    # Assess ASN retrieval
    asn_success = retrieve.asn(exposure)
    logger.debug(
        f"\n`->\tAsn retrieval: "
        f"{exposure[0].asn.number if exposure[0].asn else 'No ASN retrieved!'}"
    )

    assert asn_success is not None
    assert exposure[0].asn
    assert exposure[0].asn.subnets

    # Assess Port retrieval
    ports_success = retrieve.ports(exposure)
    logger.debug(
        f"\n`->\tPorts retrieval: "
        f"{exposure[0].ports if exposure[0].ports else 'No Ports retrieved!'}"
    )

    assert ports_success is not None
    assert exposure[0].ports
    assert len(exposure[0].ports) > 0

    # Assess Hostnames retrieval
    hostnames_success = retrieve.hostnames(exposure)
    logger.debug(
        f"\n`->\tHostnames retrieval: "
        f"{exposure[0].hostnames if exposure[0].hostnames else 'No Hostnames retrieved!'}"
    )

    assert hostnames_success is not None
    assert exposure[0].hostnames
    assert len(exposure[0].hostnames) > 0
