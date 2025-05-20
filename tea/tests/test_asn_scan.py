"""Test ASN scan functionality."""

import logging
from ipaddress import IPv4Network

from tea import scan

logger = logging.getLogger(__name__)


def test_asn_scan_success(requests_mock, target_host):
    """Test the ASN scan functionality with mocked API responses."""
    logger.debug(
        "\n\nTESTING ASN SCAN FUNCTION AND API RESPONSES"
        "\n-------------------------------------------"
    )

    # A "fake" API response for the ASN lookup by IP
    ip_response = {
        "asn": "AS15169",
        "asn_name": "GOOGLE",
        "asn_range": "8.8.8.0/24",
        "description": "Google LLC",
    }

    # A "fake" API response for the ASN lookup by ASN
    asn_subnet_response = {"prefixes": ["8.8.8.0/24", "8.8.4.0/24"]}

    # IP -> ASN lookup request
    requests_mock.get(
        "https://api.hackertarget.com/aslookup/?q=8.8.8.8&output=json&details=true",
        json=ip_response,
    )

    # ASN -> Subnet lookup request
    requests_mock.get(
        "https://api.hackertarget.com/aslookup/?q=AS15169&output=json&details=true",
        json=asn_subnet_response,
    )

    # Perform the ASN scan
    scan.asn(target_host)

    assert target_host.asn is not None
    assert target_host.asn.number == "AS15169"
    assert len(target_host.asn.subnets) == 2
    expected_subnets = [IPv4Network("8.8.4.0/24"), IPv4Network("8.8.8.0/24")]
    assert target_host.asn.subnets == expected_subnets
