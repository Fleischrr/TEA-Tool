"""Initialization and configuration for the TEA-Tool."""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)


def startup_actions() -> None:
    """
    Perform necessary startup actions for the TEA-Tool.

    This function needs to be called at the beginning of the program to ensure
    that all required initializations and configurations are done.
    """
    tea_root = Path(__file__).resolve().parent.parent

    # Load variables from the .env file into the environment
    load_dotenv(dotenv_path=tea_root / ".env")

    # Clear existing handlers (useful in testing)
    logging.root.handlers.clear()

    log_path = os.getenv("LOG_PATH")
    if not log_path:
        log_path = str(tea_root / ".tea.log")
        os.environ["LOG_PATH"] = log_path
    else:
        log_path = Path(log_path)

    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_path)],
    )

    # Check the DB-path and set to default if not set
    db_path: str = os.getenv("EXPOSURE_DB_PATH")
    if not db_path:
        db_path = str(tea_root / ".exposure.sqlite")
        os.environ["EXPOSURE_DB_PATH"] = db_path

    # Check the schedule path and set to default if not set
    schedule_path: str = os.getenv("SCHEDULE_PATH")
    if not schedule_path:
        schedule_path = str(tea_root / "schedule.json")
        os.environ["SCHEDULE_PATH"] = schedule_path
