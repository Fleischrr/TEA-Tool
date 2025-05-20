"""Test inserting TargetHosts into the database."""

import logging
import time

from tea import db, models
from tea.models.port import Port

logger = logging.getLogger(__name__)


def test_insert_target_host(target_host):
    """Assert insert of TargetHost into the database."""
    logger.debug(
        "\n\nTESTING DB INSERT/UPDATE FUNCTIONALITY\n--------------------------------------"
    )

    # Check db connection
    conn = db.get_connection()
    assert conn is not None
    conn.close()

    # Assess insertion
    exposure: list[models.TargetHost] = [target_host]

    assert db.save_discovery(exposure)
    assert db.save_full(exposure)


def test_update_target_host(target_host):
    """Assert update of TargetHost into the database."""
    logger.debug("\n`->\tDB update assertion")
    exposure: list[models.TargetHost] = [target_host]

    # Assert update insertion
    time.sleep(3)
    logger.debug("\n`->\tDiscovery Scan assertion")
    target_host.os = "Windows"
    assert db.save_discovery(exposure)

    logger.debug("\n`->\tFull Scan assertion")
    target_host.ports[1] = Port(
        number=80,
        protocol="udp",
        hostnames=["web", "test.web"],
        service="HTTP",
        http_status=301,
        http_header="HTTP/1.1 200 OK",
        vulns=["CVE-2021-1234"],
        opts=["DEATH DHE"],
    )

    assert db.save_full(exposure)
