"""Handles the menu views of the TEA-Tool."""

from rich.console import Console
from rich.prompt import Prompt

from tea import scan, ui, utils

console = Console()


def menu_screen() -> bool:
    """
    Display the main menu screen for the TEA-Tool.

    This function displays the main menu and handles user input for various
    functionalities of the TEA-Tool.

    :return: True if the user wants to continue, False if they want to exit.
    :rtype: bool
    """
    ui.show_welcome_screen()

    if utils.get_shodan_api() is None:
        console.print(
            "[green]TEA-Tool[/]> [cyan]Menu Selection[/] [yellow]SHODAN API Key not found![/]"
        )

    commands = [
        "v",  # View Exposure
        "h",  # Help
        "c",  # Config
        "q",  # Quit
        "f",  # Full Scan
        "d",  # Discovery Scan
    ]

    while True:
        try:
            user_input = Prompt.ask(
                "[green]TEA-Tool[/]> [cyan]Menu Selection[/]",
                choices=commands,
                case_sensitive=False,
                show_default=True,
                default="h",
                show_choices=False,
            )

            match user_input:
                case "h":  # Help
                    ui.help_screen()
                    break
                
                case "c":  # Config
                    while ui.config_screen():
                        continue
                    break

                case "d":  # Discovery Scan
                    domain, country_codes, save = ui.discovery_scan_menu()
                    console.clear()

                    if not domain:
                        break

                    exposure = scan.discovery(domain=domain, country_codes=country_codes, save=save)  # type: ignore
                    ui.schedule_scan_menu(
                        scan_type="discovery",
                        domain=domain,
                        country_codes=country_codes,
                        save=save,  # type: ignore
                    )

                    input("Press Enter to continue...")
                    while ui.view_exposure() if save else ui.view_exposure(exposure):
                        continue
                    break

                case "v":  # View Exposure
                    while ui.view_exposure():
                        continue
                    break

                case "f":  # Full Scan
                    use_existing, domain, country_codes, save = ui.full_scan_menu()
                    console.clear()

                    # Perform scan according to user input
                    if domain:
                        exposure = scan.full(domain=domain, country_codes=country_codes, save=save)  # type: ignore
                    elif use_existing:
                        exposure = scan.full(use_existing=use_existing, save=save)  # type: ignore
                    else:
                        break

                    ui.schedule_scan_menu(
                        scan_type="full",
                        domain=domain if not use_existing else None,  # type: ignore
                        country_codes=country_codes if not use_existing else [],  # type: ignore
                        use_existing=use_existing,  # type: ignore
                        save=save,  # type: ignore
                    )

                    input("Press Enter to continue...")
                    while ui.view_exposure() if save else ui.view_exposure(exposure):
                        continue
                    break

                case "q":  # Quit
                    console.print("\nExiting TEA-Tool. Goodbye World!", style="bold cyan")
                    return False

        except KeyboardInterrupt:
            console.print("\nExiting TEA-Tool. Goodbye World!", style="bold cyan")
            return False

    return True
