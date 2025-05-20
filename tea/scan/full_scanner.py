"""Provides a full scan for a given domain."""

from rich.progress import Progress

from tea import db, models, scan


def full(
    use_existing: bool = False,
    domain: str | None = None,
    country_codes: list[str] | None = None,
    save: bool = True,
) -> list[models.TargetHost]:
    """
    Perform a full scan on the given domain.

    The full scan includes a Discovery Scan
    and a full IP scan for each host.

    :param use_existing: Whether to use existing exposure data (default: False).
    :type use_existing: bool
    :param domain: The domain to scan.
    :type domain: str
    :param country_codes: A list of country codes to filter the results (optional).
    :type country_codes: list[str] | None
    :param save: Whether to save the discovered hosts to the database (default: True).
    :type save: bool
    :return: A list of TargetHost objects representing the exposure.
    :rtype: list[models.TargetHost]
    """
    print(f"`- Starting Full Scan for domain: {domain}")
    exposure: list[models.TargetHost]

    if use_existing:
        exposure = db.retrieve_exposure()

        if not exposure:
            print(" | No existing exposure found.\n - Full Scan completed.")
            return []

        print(" | Existing exposure retrieved.")

    else:
        exposure = scan.discovery(domain, country_codes, save=False)

    print(f"`-- Starting IP scan for {len(exposure)} hosts...")
    with Progress() as progress:
        task = progress.add_task("  | Scanning hosts:", total=len(exposure))

        for host in exposure:
            scan.ip(host)
            progress.update(task, advance=1)

    print(" -- IP Scan for completed.")

    if save:
        print("`-- Saving results to database...")
        db.save_full(exposure)

    print(" - Full Scan completed.")
    return exposure
