"""Handles the exposure views of the TEA-Tool."""

import logging
from datetime import datetime, timedelta

from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from tea import db, models

logger = logging.getLogger(__name__)
console = Console()
SCAN_TIME_DELTA = timedelta(minutes=5)


def gen_host_summary(host: models.TargetHost):
    """
    Generate a summary of the host's exposure data.

    :param host: The target host object.
    :type host: models.TargetHost
    """
    # Panel Title
    title = f"[bold green]Exposure for {host.ip}[/bold green]"

    # Host Info
    host_info = Text()
    host_info.append(f"\nIP:\t\t{host.ip}\n")
    host_info.append(f"OS:\t\t{host.os}\n")
    host_info.append(f"Domain:\t\t{host.domain}\n")
    host_info.append(f"Org:\t\t{host.org}\n")
    host_info.append(f"Hostname(s):\t{', '.join(host.hostnames)}\n")
    host_info.append(f"ASN:\t\t{host.asn.number if host.asn else 'N/A'}\n")

    # Port Table
    port_table = Table(title="Open Ports", title_style="bold magenta")
    port_table.add_column("Port", style="bold white", justify="right")
    port_table.add_column("Protocol", style="dim")
    port_table.add_column("Service", style="cyan")
    port_table.add_column("Vulns", style="red")
    port_table.add_column("Opts", style="yellow")
    port_table.add_column("HTTP Status", style="green")
    port_table.add_column("Banner", style="green")

    for port in host.ports:
        port_table.add_row(
            str(port.number),
            port.protocol or "-",
            port.service or "-",
            ", ".join(vuln.name for vuln in port.vulns) if port.vulns else "-",
            ", ".join(opt.__str__() for opt in port.opts) if port.opts else "-",
            str(port.http_status) if port.http_status else "-",
            str(port.banner) if port.banner else "-",
        )

    # Combine text and table
    group = Group(host_info, port_table)

    console.clear()
    console.print(Panel(group, title=title, border_style="cyan"))

    input("Press any key to return...")


def gen_asn_summary(unique_asn: dict[int, models.ASN]):
    """
    Generate a summary of unique ASNs from the exposure data.

    :param unique_asn: Set of unique ASN objects.
    :type unique_asn: set[models.ASN]
    """
    console.rule(f"[bold yellow]Unique ASNs ({len(unique_asn)})[/bold yellow]")

    console.clear()
    for asn_obj in unique_asn.values():
        asn_text = Text()
        asn_text.append(f"ASN:\t\t{asn_obj.number}\n")
        asn_text.append(f"Name:\t\t{asn_obj.name}\n")
        asn_text.append(f"Description:\t{asn_obj.description}\n")
        asn_text.append(f"Subnets:\t{', '.join(str(s) for s in asn_obj.subnets)}\n")
        console.print(
            Panel(asn_text, border_style="magenta", title=f"AS{asn_obj.number}", title_align="left")
        )

    input("Press any key to return...")


def gen_top_stats(label: str, data: dict, unit: str = "host(s)", key_formatter: callable = str):  # type: ignore
    """
    Generate a summary of the top statistics from the exposure data.

    :param label: The label for the summary.
    :type label: str
    :param data: The data to summarize.
    :type data: dict
    :param unit: The unit of measurement for the summary.
    :type unit: str
    :param key_formatter: A function to format the keys in the summary.
    :type key_formatter: callable
    """
    items = sorted(data.items(), key=lambda x: x[1], reverse=True)
    section = f"{label if len(items) > 5 else label.replace('Top 5', 'Hosts by')}:\n"

    for key, count in items[:5]:
        section += f" - [cyan]{key_formatter(key)}[/cyan]: [white]{count} {unit}[/]\n"

    return section


def input_handling(unique_asn: dict[int, models.ASN], ip_map: dict[str, models.TargetHost]) -> bool:
    """
    Handle user input for viewing exposure data.

    :param unique_asn: Set of unique ASN objects.
    :type unique_asn: set[models.ASN]
    :param ip_map: Map of IP addresses to TargetHost objects.
    :type ip_map: dict[str, models.TargetHost]
    :return: True if the user wants to continue, False if they want to exit.
    :rtype: bool
    """
    commands = [
        "a",  # ASN summary
        "s",  # Host search
        "q",  # Quit
    ]

    try:
        console.print("[green]TEA-Tool[/]> [cyan]View Exposure[/]:\n")
        options = Text()
        options.append(
            "\t - Enter [a] for ASN summary.\n"
            "\t - Enter [s] to view detailed host information.\n"
            "\t - Enter [q] to return to the menu.\n"
        )
        console.print(options)

        choice = Prompt.ask(
            "[green]TEA-Tool[/]> [cyan]View Exposure[/]",
            choices=commands,
            default="q",
            case_sensitive=False,
        )

        match choice:
            case "a":
                gen_asn_summary(unique_asn)
            case "s":
                ip = Prompt.ask(
                    "[green]TEA-Tool[/]> [cyan]View Exposure[/]> IP of host to view",
                    choices=list(ip_map.keys()),
                    default="q",
                    show_choices=False,
                    case_sensitive=False,
                )

                if ip not in ip_map:
                    return True

                gen_host_summary(ip_map[ip])
            case "q":
                return False

    except KeyboardInterrupt:
        return False

    return True


def process_items(items, latest_scan, current_count, new_items_count, old_items_count, item_map):
    """
    Process a list of items (e.g., vulns and opts) and update statistics.

    :param items: The list of items to process.
    :param latest_scan: The latest scan.
    :param current_count: The current count.
    :param new_items_count: The new items count.
    :param old_items_count: The old items count.
    :param item_map: Map of items to targets.
    :return: The updated counts.

    """
    for item in items:
        created = datetime.fromisoformat(item.created_at)
        modified = datetime.fromisoformat(item.modified_at)

        if abs(latest_scan - modified) <= SCAN_TIME_DELTA:
            current_count += 1
            item_map[item.name] = item_map.get(item.name, 0) + 1

            if created == modified:
                new_items_count += 1

            else:
                old_items_count += 1

    return current_count, new_items_count, old_items_count


def view_exposure(tmp_exposure: list[models.TargetHost] | None = None) -> bool:
    """
    Display the exposure data in a user-friendly overview format.

    This function retrieves the exposure data from the database and presents it
    in a table format. It also provides options for the user to view ASN summaries
    or search for specific hosts.

    :return: True if the user wants to continue, False if they want to exit.
    :rtype: bool
    """
    if tmp_exposure is None:
        logger.debug("Retrieving exposure data from the database.")

        if db.get_connection(check=True) is None:
            console.print("[bold red]Database not initialized, cannot view exposure.[/bold red]")
            return False
        
        exposure: list[models.TargetHost] = db.retrieve_exposure()

        if not exposure:
            console.print("[bold red]No exposure data found in the database.[/bold red]")
            return False
    else:
        logger.debug("Using temporary exposure data.")
        exposure = tmp_exposure
    
    # Ready terminal for output
    console.clear()

    # Compact summary view
    table = Table(title="Exposure Overview", title_style="bold cyan")
    table.add_column("IP Address", style="bold white")
    table.add_column("Hostnames", justify="right")
    table.add_column("Ports [dim]([green]+[/]/[red]-[/])[/]", justify="center")
    table.add_column("Domain", style="dim")
    table.add_column("Organization", style="dim")
    table.add_column("ASN", style="cyan")
    table.add_column("Notes [dim]([green]+[/]/[red]-[/])[/]", style="yellow", justify="center")

    # Different maps and counters for statistics
    ip_map = {}  # IP -> TargetHost
    asn_map = {}  # ASN -> host count
    unique_asn = {}  # ASN Number -> ASN Object
    port_count = {}  # Port Number -> count of hosts
    vuln_opt_map = {}  # Vulnerability/Optional -> count of hosts
    service_map = {}  # Service -> count of hosts

    host_w_vulns: int = 0
    host_w_opts: int = 0

    latest_scan: datetime = max(
        datetime.fromisoformat(host.modified_at) for host in exposure if host.modified_at
    )

    for host in exposure:
        ip_map[str(host.ip)] = host

        if host.asn:
            # Map unique ASNs to ASN objects
            if host.asn.number not in unique_asn:
                unique_asn[host.asn.number] = host.asn

            # Map number of hosts to ASN
            if host.asn.number in asn_map:
                asn_map[host.asn.number] += 1
            else:
                asn_map[host.asn.number] = 1

        # Port counts
        current_ports: int = 0
        new_ports_count: int = 0
        old_ports_count: int = 0

        # Vuln and opt counts
        vulns_count: int = 0
        opts_count: int = 0
        new_opt_vuln_count: int = 0
        old_opt_vuln_count: int = 0

        for port in host.ports:
            port_created = datetime.fromisoformat(port.created_at)
            port_modified = datetime.fromisoformat(port.modified_at)

            # If port is current
            if abs(latest_scan - port_modified) <= SCAN_TIME_DELTA:
                current_ports += 1

                if port_created == port_modified:
                    new_ports_count += 1

                # Map ports
                port_count[port.number] = port_count.get(port.number, 0) + 1

                # Map service
                if port.service:
                    service_map[port.service] = service_map.get(port.service, 0) + 1

            else:
                # If port is old
                old_ports_count += 1

            vulns_count, new_opt_vuln_count, old_opt_vuln_count = process_items(
                port.vulns,
                latest_scan,
                vulns_count,
                new_opt_vuln_count,
                old_opt_vuln_count,
                vuln_opt_map,
            )

            opts_count, new_opt_vuln_count, old_opt_vuln_count = process_items(
                port.opts,
                latest_scan,
                opts_count,
                new_opt_vuln_count,
                old_opt_vuln_count,
                vuln_opt_map,
            )

        # Set style based on criticality
        if vulns_count > 0:
            base_style = "red"
            host_w_vulns += 1
        elif opts_count > 0:
            base_style = "yellow"
            host_w_opts += 1
        else:
            base_style = "green"

        ip_text = Text(str(host.ip), style=base_style)

        # Dim the row if it was not in the latest scan
        row_style = None
        host_scan_time = datetime.fromisoformat(host.modified_at)
        if abs(latest_scan - host_scan_time) > SCAN_TIME_DELTA:
            row_style = "dim"

        # Generate port trend text
        port_text = ""
        if new_ports_count > 0:
            port_text += f"[green]↑{new_ports_count}[/]"

        if old_ports_count > 0:
            port_text += f"[red]↓{old_ports_count}[/]"

        if new_ports_count == 0 and old_ports_count == 0:
            port_text += "[dim]0[/]"

        # Generate vuln/opt trend text
        vuln_opt_text = ""
        if new_opt_vuln_count > 0:
            vuln_opt_text += f"[green]↑{new_opt_vuln_count}[/]"

        if old_opt_vuln_count > 0:
            vuln_opt_text += f"[red]↓{old_opt_vuln_count}[/]"

        if new_opt_vuln_count == 0 and old_opt_vuln_count == 0:
            vuln_opt_text += "[dim]0[/]"

        # Set the row order
        table.add_row(
            ip_text,
            str(len(host.hostnames)),
            str(len(host.ports)) + f" ({port_text})",
            host.domain or "-",
            host.org or "-",
            host.asn.number if host.asn else "N/A",
            str(vulns_count + opts_count) + f" ({vuln_opt_text})",
            style=row_style,
        )

    logger.debug("Exposure retireved and processed, printing view.")
    console.print(table)

    # Summary text
    summary = Layout()

    # Summary left
    overview_row = "Shaded [dim]hosts[/] have not been seen in the latest scan.\n\n"
    overview_row += f"Total hosts: [bold cyan]{len(exposure)}[/bold cyan]\t\t\t"
    overview_row += f"Unique ASNs: [bold cyan]{len(asn_map)}[/bold cyan]\t\t\t"
    overview_row += f"Unique ports: [bold cyan]{len(port_count)}[/bold cyan]\n"

    # Summary middle
    overview_row += (
        f"Total [bold red]hosts[/bold red] with vulns: [bold red]{host_w_vulns}[/bold red]\t"
    )
    overview_row += (
        f"Total [bold yellow]hosts[/bold yellow] with opts: "
        f"[bold yellow]{host_w_opts}[/bold yellow]\t"
    )
    overview_row += (
        f"Total [bold green]hosts[/bold green] with nothing: "
        f"[bold green]{len(exposure) - (host_w_vulns + host_w_opts)}[/bold green]\n"
    )

    overview_row = Layout(overview_row, size=5)

    # Stat rows
    top_stat_row = Layout()
    port_stats = gen_top_stats("Top 5 ports", port_count)
    service_stats = gen_top_stats("Top 5 services", service_map)

    bottom_stat_row = Layout()
    vuln_opt_stats = gen_top_stats("Top 5 vulns/opts", vuln_opt_map)
    asn_stats = gen_top_stats("Top 5 ASNs", asn_map, key_formatter=lambda number: f"AS{number}")

    top_stat_row.split_row(port_stats, service_stats)
    bottom_stat_row.split_row(vuln_opt_stats, asn_stats)

    summary.split(
        overview_row,
        top_stat_row,
        bottom_stat_row,
    )

    console.print(
        Panel(summary, title="Exposure Summary", border_style="green", height=21, width=120)
    )

    return input_handling(unique_asn, ip_map)
