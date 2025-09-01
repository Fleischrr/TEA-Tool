"""Handles the welcome screen for the TEA-Tool."""

from pathlib import Path

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text

CURRENT_DIR = Path(__file__).parent
ASSETS_DIR = CURRENT_DIR / "assets"

console = Console()


def gen_logo_panel() -> Panel | None:
    """
    Generate the logo panel for the TEA-Tool.

    :return: Panel object containing the logo or None if the logo cannot be generated.
    :rtype: Panel | None
    """
    logo_path = ASSETS_DIR / "tea_logo.txt"

    width, height = 160, 33
    min_width, min_height = 80, 33
    current_size = console.size

    if current_size.width < width or current_size.height < height:
        if current_size.width < min_width or current_size.height < min_height:
            return None
        logo_path = ASSETS_DIR / "tea_logo_small.txt"

    try:
        with logo_path.open("r", encoding="utf-8") as logo_file:
            logo = logo_file.read()
        return Panel(logo, border_style="green", title="TEA-Tool")

    except FileNotFoundError:
        logo = "Logo file not found."
        return None
    except PermissionError:
        logo = "Permission denied while reading the logo file."
        return None


def gen_splash_panel() -> Panel:
    """
    Generate the splash panel for the TEA-Tool.

    :return: Panel object containing the splash screen.
    :rtype: Panel
    """
    welcome = Text(justify="center")
    welcome.append("\nThreat Exposure Analysis Tool\n", style="bold green")
    welcome.append("\nhttps://github.com/Fleischrr/TEA-Tool\n", style="dim")
    welcome.append("Author: ", style="white")
    welcome.append("Fleischrr\n", style="bold white")
    welcome.append("Version: 1.1.1\n", style="dim")
    welcome.append("\n\"You can't protect what you don't know about.\"", style="dim italic")

    return Panel(welcome)


def gen_info_panel() -> Panel:
    """
    Generate the information panel for the TEA-Tool.

    :return: Panel object containing the information screen.
    :rtype: Panel
    """
    info = Text(justify="left")

    # Introduction info
    info.append("\nThe ")
    info.append("TEA-Tool ", style="green")
    info.append("is an open-source Threat Exposure Analysis CLI Tool. ")
    info.append(
        "The purpose of the tool is to help organizations map their external digital presence "
        "through domain discovery, ASN lookup, IP and port scanning. "
    )
    info.append(
        "All without directly interacting with or retrieving data from the target, "
        "but by only using publicly available data.\n"
    )

    # Additional info
    info.append("\n[!!] ", style="bold yellow")
    info.append(
        "A Shodan API key is recommended for the full retrieval of details.\n", style="yellow"
    )

    info.append("\n[!!] ", style="bold yellow")
    info.append("Set the SHODAN API key in a file under the TEA-Tool directory named ")
    info.append(".env ", style="bold yellow")
    info.append("to apply the API key persistently.")

    # Usage info
    info.append("\n\n\n  General:\n\n")
    info.append("\t[v]: ", style="bold white")
    info.append("View Exposure", style="cyan")
    info.append("\t[h]: ", style="bold white")
    info.append("Help", style="cyan")
    info.append("\t[c]: ", style="bold white")
    info.append("Configuration", style="cyan")
    info.append("\t[q]: ", style="bold white")
    info.append("Quit", style="cyan")

    info.append("\n\n\n  Scanning:\n\n")
    info.append("\t[f]: ", style="bold white")
    info.append("Full Scan", style="green")
    info.append("\t\t[d]: ", style="bold white")
    info.append("Discovery Scan", style="green")

    return Panel(info, title="Information", border_style="cyan bold", title_align="left")


def show_welcome_screen():
    """
    Show the welcome screen for the TEA-Tool.

    This function displays the welcome screen layout, including the logo,
    splash screen, and information panel.
    """
    height: int | None = 33
    output = Layout(name="row")

    # Create the layout
    welcome = Layout(name="welcome", size=10)
    info = Layout(name="info", size=23)
    logo = Layout(name="logo", size=80)

    right_column = Layout(name="right_column")
    right_column.split(welcome, info)

    # Check if the logo panel can be generated
    if gen_logo_panel():
        if console.size.width < 160:
            # Use a different layout if the logo panel is small
            height = 41
            logo.size = 42
            welcome.size = None
            row = Layout(name="row", size=18)

            # Move logo into the welcome panel
            row.split_row(logo, welcome)
            row["logo"].update(gen_logo_panel())  # type: ignore
            output.split(row, info)

        else:
            # Standard logo layout
            output.split_row(logo, right_column)
            output["logo"].update(gen_logo_panel())  # type: ignore

    else:
        # Smallest layout if no logos can be generated
        output = right_column

    output["welcome"].update(gen_splash_panel())
    output["info"].update(gen_info_panel())

    console.clear()
    console.print(output, height=height)
