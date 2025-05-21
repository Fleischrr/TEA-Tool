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

    if not api_key:
        console.print(
            "[green]TEA-Tool[/]> [cyan]SHODAN API Key[/]> [bold red]SHODAN API key not found!\n[/]"
            "[green]TEA-Tool[/]> [cyan]SHODAN API Key[/]> "
            "Set [yellow]SHODAN_API_KEY=<KEY>[/] in a [cyan].env[/cyan] file under the TEA-Tool "
            "directory to store it persistently or enter it below for temporary use."
        )

        try:
            while True:
                console.print("[green]TEA-Tool[/]> [cyan]SHODAN API Key[/]> ", end="")
                key = input("Enter SHODAN API key: ").strip()

                if key and len(key) == 32:
                    os.environ["SHODAN_API_KEY"] = key
                    api_key = key
                    break
                else:
                    console.print(
                        "[green]TEA-Tool[/]> [cyan]SHODAN API Key[/]> Invalid key, try again."
                    )
                    continue

        except KeyboardInterrupt:
            console.print(
                "[green]TEA-Tool[/]> \n\n[purple bold]Exiting TEA-Tool. Goodbye World![/]\n"
            )
            return None

    logger.debug(f"SHODAN API key: {api_key}")
    return shodan.Shodan(api_key)
