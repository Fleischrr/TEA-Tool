"""Handle command line arguments for the TEA-Tool."""

import argparse


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments for the TEA-Tool.

    This function sets up the argument parser and defines the
    command line arguments that can be used when running the TEA-Tool.

    :return: Parsed command line arguments.
    :rtype: argparse.Namespace
    """
    # Define the argument parser
    arg_parser = argparse.ArgumentParser(
        description=("The TEA-Tool.\nAn open-source Threat Exposure Analysis CLI Tool."),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Create a group for optional arguments
    group = arg_parser.add_argument_group(
        "Optional arguments", "Headless options to schedule scans or export data."
    )

    # Make a mutually exclusive group for schedule and export
    exclusive_group = group.add_mutually_exclusive_group()
    exclusive_group.add_argument(
        "-s",
        "--schedule",
        metavar="../path/to/config.json",
        help="Schedule configuration file path",
    )
    exclusive_group.add_argument(
        "-x",
        "--export",
        metavar="../path/to/output.csv",
        help="Path to exported TEA exposure data (CSV format)",
    )

    return arg_parser.parse_args()
