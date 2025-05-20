"""Configures the test environment for pytest."""

import logging
import os
from ipaddress import IPv4Address

import pytest
from tea import models, utils
from tea.models.port import Port

os.environ["LOG_PATH"] = "tea/tests/.test.log"
os.environ["EXPOSURE_DB_PATH"] = "tea/tests/.test_db.sqlite"

utils.startup_actions()

logger = logging.getLogger(__name__)
logger.debug(
    "\n\n-------------------------------------------"
    "\n\tStarting tests"
    "\n-------------------------------------------"
)


@pytest.fixture(scope="session")
def target_host() -> models.TargetHost:
    """Create a fake TargetHost for testing."""
    host = models.TargetHost(IPv4Address("8.8.8.8"))
    host.add_hostnames(["example", "test", "web.example", "test.example"])
    host.os = "Linux"
    host.domain = "example.com"
    host.org = "Example Org"
    host.add_ports([80, 443, 22])
    host.ports[0] = Port(
        number=21,
        protocol="tcp",
        hostnames=["test", "web.example"],
        service="Telnet",
        http_status=200,
        http_header="HTTP/1.1 200 OK",
        vulns=["CVE-2021-1234"],
        opts=["DEATH DHE"],
    )

    return host
