"""This is the main entry point for the TEA-Tool."""

import sys
import logging

import tea

logger = logging.getLogger(__name__)


def main():  # noqa: D103
    # Initialize startup actions
    tea.utils.startup_actions()

    # Retrieve command line arguments
    args = tea.utils.parse_args()

    if args.schedule:
        # Run the TEA-Tool with a schedule scan
        try:
            tea.utils.schedule_scan(args.schedule)
            sys.exit(0)

        except Exception as e:
            logger.error(f"Error running schedule scan: {e}")
            sys.exit(1)

    elif args.export:
        # Export the TEA exposure to a CSV file
        try:
            tea.utils.export_to_csv(args.export)
            sys.exit(0)

        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            sys.exit(1)

    else:
        # Run the TEA-Tool interactively
        while True:
            should_continue = tea.ui.menu_screen()

            if not should_continue:
                break


if __name__ == "__main__":
    main()
