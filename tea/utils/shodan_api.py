"""Utility function that initializes the SHODAN API client."""

import logging
import os
from pathlib import Path

import shodan
from dotenv import get_key, set_key
from rich.console import Console

logger = logging.getLogger(__name__)

console = Console()

TEA_ROOT = Path(os.getenv("TEA_ROOT", os.getcwd())) 


def get_shodan_api() -> shodan.Shodan:
    """
    Initialize and return a SHODAN API client using the API key from a .env file.

    :return: An instance of the SHODAN API client.
    :rtype: shodan.Shodan
    """
    # Get SHODAN API key from the environment
    api_key = get_key(dotenv_path=TEA_ROOT / ".env", key_to_get="SHODAN_API_KEY")
    
    logger.debug(f"Retrieved API key from environment: {api_key}")

    return shodan.Shodan(api_key)
    

def set_shodan_api(api_key) -> bool:
    """
    Set the SHODAN API key in the environment.

    :param api_key: The SHODAN API key to verify.
    :type api_key: str
    :return: The status for settingthe API key.
    :rtype: bool
    """
    if not verify_shodan_key(api_key):
        return False
    
    set_key(
        dotenv_path=TEA_ROOT / ".env", key_to_set="SHODAN_API_KEY", value_to_set=api_key
    )
    logger.info("SHODAN API key set.")

    return True


def verify_shodan_key(api_key: str) -> bool:
    """
    Verify the given SHODAN API key.

    :param api_key: The SHODAN API key to verify.
    :type api_key: str
    :return: An instance of the SHODAN API client.
    :rtype: shodan.Shodan
    """
    if api_key is None or len(api_key.strip()) < 32:
        logger.error("SHODAN API key is too short!")
        return False
        
    try:
        shodan_object = shodan.Shodan(api_key.strip())
        output = shodan_object.info()
        logger.debug(f"SHODAN API key veryfied: {output}")
        return True
    
    except shodan.APIError as shodan_api_error:
        logger.error(shodan_api_error)
        return False
    
    except Exception as general_exception:
        logger.error(f"Error initializing SHODAN API client: {general_exception}")
        return False
