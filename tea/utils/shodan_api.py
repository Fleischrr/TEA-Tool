"""Utility function that initializes the SHODAN API client."""

import logging
import os

import shodan
from rich.console import Console

logger = logging.getLogger(__name__)

console = Console()


def get_shodan_api() -> shodan.Shodan | None:
    """
    Initialize and return a SHODAN API client using the API key from a .env file.

    :return: An instance of the SHODAN API client.
    :rtype: shodan.Shodan
    :raises ValueError: If the SHODAN_API_KEY environment variable is not set.
    """
    # Get SHODAN API key from the environment
    api_key = os.getenv("SHODAN_API_KEY")

    if api_key is None:
        return None

    try:
        shodan_object = shodan.Shodan(api_key)

    except shodan.APIError:
        return None

    return shodan_object
