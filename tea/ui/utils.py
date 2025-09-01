"""Handles the utility views of the TEA-Tool."""

import os
from pathlib import Path

from dotenv import set_key
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text

from tea import utils

console = Console()

def config_screen():
    """Display the configuration view for the TEA-Tool."""
    #choice: str = ""

    while True:
        choice = Prompt.ask(
            "[green]TEA-Tool[/]> [cyan]Configuration[/] > "
            "What do you want to [yellow]configure[/]?",
            default="q",
            choices=["a", "q"],
            case_sensitive=False,
        )
        
        if not choice:
            continue
        break

    tea_root  = Path(str(os.getenv("TEA_ROOT")))

    if choice == "a":
        shodan_api_key = Prompt.ask(
            "[green]TEA-Tool[/]> [cyan]Configuration[/] > [yellow]SHODAN API Key:[/]",
            default="",
        )
        if shodan_api_key is not None:
           set_key(dotenv_path=tea_root / ".env", key_to_set="SHODAN_API_KEY", value_to_set=shodan_api_key)
           shodan_key_appllied = utils.get_shodan_api

    elif choice == "q":
        return False


def help_screen():
    """Display the help view for the TEA-Tool."""
    help_text = Text(justify="left")

    # Key features info
    help_text.append("\nKey Functionalities:\n\n", style="bold green")
    help_text.append("   Discovery Scan", style="cyan")
    help_text.append(" (d)\n", style="green")
    help_text.append(
        "Uses DNS records and SHODAN search to identify ASNs, hostnames and related IPs.\n"
        "Requires a domain name to start the scan. "
        "Results can be populated even more by providing country codes,\n"
        "but this may introduce unwanted hosts in the exposure.\n\n"
    )
    help_text.append("   Full Scan", style="cyan")
    help_text.append(" (f)\n", style="green")
    help_text.append(
        "Extends the Discovery Scan by retrieving detailed port, HTTP, and vulnerability data.\n"
        "Can also use saved exposure received from a prior Discovery Scan.\n\n"
    )
    help_text.append("   View Exposure", style="cyan")
    help_text.append(" (v)\n", style="green")
    help_text.append(
        "Displays the exposure in a summary or detailed format.\n"
        "Requires exposure to be populated and saved in the database.\n\n"
    )
    help_text.append("   Scheduled Scan \n", style="cyan")
    help_text.append(
        "Run the TEA-Tool on a schedule (e.g. cron) "
        "by passing a configuration file as argument.\n"
        "After each scan, you will be prompted to save your scan configuration to a file.\n"
        "Pass this file as an argument for scheduled, silent CLI execution.\n"
        "Usage: python tea_tool.py [-s or --schedule] /path/to/schedule.json\n"
        "The configuration file defines the scan type and options to use.\n\n"
    )

    # Input options info
    help_text.append("\nInput Options:\n", style="bold green")
    help_text.append(
        "Both the Full Scan and the Discovery Scan require the same input options.\n"
        "The only variation is that the Full Scan can use existing exposure "
        "from a previous Discovery or Full Scan.\n\n"
    )
    help_text.append("   Domain Name (Required)\n", style="cyan")
    help_text.append("The domain name to scan. E.g. example.com\n\n")
    help_text.append("   Country Code(s) (Optional)\n", style="cyan")
    help_text.append(
        "A list of country codes to filter results (e.g. NO, DK, US, CA).\n"
        "Filters a search for just the domain name (i.e. example) by given country code(s).\n\n"
    )
    help_text.append("   Save to Database (Optional)\n", style="cyan")
    help_text.append(
        "Save the results to a database for later retrieval or use in a Full Scan.\n\n"
    )

    # Additional info
    help_text.append("\nAdditional Information:\n\n", style="bold green")
    help_text.append(
        "  - Scans do not interact directly with the targets,\n"
        "data is collected from SHODAN or other public sources.\n\n"
        "  - A paid SHODAN API key will retrieve more detailed information.\n"
        "Set the key in the .evn file with SHODAN_API_KEY=<key> or "
        "during startup for temporary use.\n\n"
        "  - A paid SHODAN API key enables the tool to retrieve more hosts during discovery.\n\n"
        "  - A paid SHODAN API key IS NOT required for the tool to function,\n"
        "but it is recommended for the full intended functionality.\n\n"
        "  - Will use the HackerTarget API to retrieve discovery if the "
        "SHODAN API key is non-paid.\n\n"
        "  - Custom paths for the SQLite database and log file can\n"
        "be set in the .env file with EXPOSURE_DB_PATH=<path> and LOG_PATH=<path>.\n"
    )

    console.clear()
    console.print(Panel(help_text, title="Help", border_style="cyan bold", title_align="left"))

    try:
        Prompt.ask("[green]TEA-Tool[/]> [cyan]Help[/]> Press any key to return to the main menu")
    except KeyboardInterrupt:
        return
