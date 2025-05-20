"""Handles the scan views for the TEA tool."""

import json
import logging
import os
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from tea import utils

logger = logging.getLogger(__name__)
console = Console()


def add_options_info(text_block: Text):
    """
    Append options information to the given text block.

    This includes details about the input needed for scans,
    such as domain name, country codes, and whether to save to the database.

    :param text_block: The text block to append information to.
    :type text_block: Text
    """
    # Input text
    text_block.append("\nInputs Needed:\n", style="green")
    text_block.append(
        "    * Domain name (e.g., example.com)\n\t"
        "- Uses DNS records and Shodan search to find IPs, hostnames and ASNs\n"
    )
    text_block.append(
        "    * Optional: Country codes (e.g., NO, SE, DE)\n\t"
        "- Uses Shodan search with the name from given domain (e.g. example) "
        "+ country codes (might introduce hosts out of scope!)",
        style="dim",
    )
    text_block.append(
        "\n    * Optional: Save to database (default: yes)\n"
        "\t- Saves results to the Exposure database.",
        style="dim",
    )


def add_options_prompt(scan_type: str):
    """
    Prompt the user for input options for scans.

    This includes both Full and Discovery scans. The function validates the input
    and returns the domain name, country codes, and whether to save to the database.

    :param scan_type: The type of scan (e.g., "Full" or "Discovery").
    :type scan_type: str
    """
    # Domain input
    while True:
        domain = Prompt.ask(
            f"[green]TEA-Tool[/]> [cyan]{scan_type} Scan[/]> Enter [yellow]Domain[/] Name",
            default=None,
            show_default=False,
            case_sensitive=False,
        )

        if not domain or not utils.validate_domain(domain_name=domain):
            console.print(
                f"[green]TEA-Tool[/]> [cyan]{scan_type} Scan[/]> [yellow]Invalid domain. "
                f"Please try again.[/]"
            )
            continue

        break

    console.print(
        f"[green]TEA-Tool[/]> [cyan]{scan_type} Scan[/]> Domain entered: [bold cyan]{domain}[/]"
    )

    # Countries input
    country_codes: list[str] | None = None
    choice = Prompt.ask(
        f"[green]TEA-Tool[/]> [cyan]{scan_type} Scan[/]> "
        f"Do you want to enter [yellow]Country Codes[/]?",
        default="n",
        choices=["y", "n"],
        case_sensitive=False,
    )

    if choice == "y":
        # Country codes input
        country_inputs = Prompt.ask(
            f"[green]TEA-Tool[/]> [cyan]{scan_type} Scan[/]> "
            f"Enter [yellow]Country Codes[/] (e.g., NO, SE, DE)"
        )
        country_codes = [
            country.strip() for country in country_inputs.split(",") if country.strip()
        ]

    # Save to DB input
    save_to_db = Prompt.ask(
        f"[green]TEA-Tool[/]> [cyan]{scan_type} Scan[/]> Save to the [yellow]Database[/]?",
        default="y",
        choices=["y", "n"],
        case_sensitive=False,
    )

    save: bool = True
    if save_to_db == "n":
        save = False

    console.print(f"[cyan]Domain: {domain}, Countries: {country_codes}, Save: {save}[/]")
    ready = Prompt.ask(
        f"[green]TEA-Tool[/]> [cyan]{scan_type} Scan[/]> Ready to start scan?",
        default="n",
        choices=["y", "n"],
        case_sensitive=False,
    )

    if ready != "y":
        console.print(f"[green]TEA-Tool[/]> [cyan]{scan_type} Scan[/]> [yellow]Scan cancelled.[/]")
        return None, None, None

    return domain, country_codes, save


def full_scan_menu():
    """Handle the Full Scan menu for the TEA tool."""
    # Description text
    description = Text(justify="left")
    description.append("\nDescription:\n", style="green")
    description.append(
        'Performs a "Discovery Scan" followed by detailed IP scans '
        "(port scanning, HTTP headers, vulnerabilities etc.).\n"
        "Saves results to the Exposure database by default. "
        "Can be re-run to update results if results are saved.\n",
        style="white",
    )

    add_options_info(description)
    console.print(Panel(description, border_style="cyan", title="Full Scan", title_align="left"))

    # Input handling
    try:
        ready = Prompt.ask(
            "[green]TEA-Tool[/]> [cyan]Full Scan[/]> Ready to start scan?",
            default="n",
            choices=["y", "n"],
            case_sensitive=False,
        )

        if ready == "n":
            return None, None, None, None

        action = Prompt.ask(
            "[green]TEA-Tool[/]> [cyan]Full Scan[/]> Use existing exposure?",
            default="n",
            choices=["y", "n"],
            case_sensitive=False,
        )

        if action == "y":
            # Save to DB input
            save: bool = True
            console.print("[green]TEA-Tool[/]> [cyan]Full Scan[/]> Using existing exposure.")
            save_to_db = Prompt.ask(
                "[green]TEA-Tool[/]> [cyan]Full Scan[/]> Save to [yellow]Database[/]?",
                default="y",
                choices=["y", "n"],
                case_sensitive=False,
            )

            if save_to_db == "n":
                save = False

            ready = Prompt.ask(
                "[green]TEA-Tool[/]> [cyan]Full Scan[/]> "
                "Ready to start scan with existing exposure?",
                default="n",
                choices=["y", "n"],
                case_sensitive=False,
            )

            if ready != "y":
                console.print("[green]TEA-Tool[/]> [cyan]Full Scan[/]> [yellow]Scan cancelled.[/]")
                return None, None, None, None

            return True, None, None, save

        domain, country_codes, save = add_options_prompt("Full")

        if not domain:
            return None, None, None, None

        return False, domain, country_codes, save

    except KeyboardInterrupt:
        return None, None, None, None


def schedule_scan_menu(
    scan_type: str,
    domain: str,
    country_codes: list[str],
    use_existing: bool = False,
    save: bool = True,
):
    """
    Display the schedule scan menu for the TEA tool.

    This function prompts the user to create a schedule config file
    for the given scan type and domain. It saves the configuration
    to a default or specified path in the .env file.

    :param scan_type: The type of scan (e.g., "Full" or "Discovery").
    :type scan_type: str
    :param domain: The domain to scan.
    :type domain: str
    :param country_codes: A list of country codes to filter the results.
    :type country_codes: list[str]
    :param use_existing: Whether to use existing exposure (default: False).
    :type use_existing: bool
    :param save: Whether to save the discovered hosts to the database (default: True).
    :type save: bool
    """
    answer = Prompt.ask(
        "Would you like to generate a schedule config file for this scan?",
        default="n",
        choices=["y", "n"],
        case_sensitive=False,
    )

    if answer != "y":
        return

    config = {
        "scan_type": scan_type,
        "domain": domain,
        "country_codes": country_codes,
        "use_existing": use_existing,
        "save": save,
    }

    schedule_path = os.getenv("SCHEDULE_PATH")
    if Path(schedule_path).exists():
        logger.debug("Schedule path already exists, overwriting.")

    try:
        Path(schedule_path).parent.mkdir(parents=True, exist_ok=True)
        with open(schedule_path, "w", encoding="utf-8") as file:
            json.dump(config, file, indent=4)

        console.print(f"Schedule config file created at {schedule_path} for {scan_type} scan.")

    except Exception as e:
        console.print(
            f"[red]TEA-Tool[/]> [cyan]{scan_type} Scan[/]> "
            f"[yellow]Error creating schedule path: {e}[/]"
        )
        return


def discovery_scan_menu():
    """Handle the discovery scan menu for the TEA tool."""
    # Description text
    description = Text(justify="left")
    description.append("\nDescription:\n", style="green")
    description.append(
        "Performs a discovery scan for given domain. "
        "Scans DNS records, searches Shodan for domain and domain name + country codes.\n"
        "Searches for ASN information (number, subnet, name etc.) "
        "and groups hosts into their related ASN subnets.\n"
        "Can be re-run to update results if results are saved. "
        "Found exposure can also be used in a full scan.\n",
        style="white",
    )

    add_options_info(description)
    console.print(
        Panel(description, border_style="cyan", title="Discovery Scan", title_align="left")
    )

    # Input handling
    try:
        action = Prompt.ask(
            "[green]TEA-Tool[/]> [cyan]Discovery Scan[/]> Ready to start scan?",
            default="n",
            choices=["y", "n"],
            case_sensitive=False,
        )

        if action == "n":
            return None, None, None

        domain, country_codes, save = add_options_prompt("Discovery")

        if not domain:
            return None, None, None

        return domain, country_codes, save

    except KeyboardInterrupt:
        return None, None, None
