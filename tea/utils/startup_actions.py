"""Initialization and configuration for the TEA-Tool."""

import logging
import os
from pathlib import Path

from dotenv import load_dotenv, set_key

logger = logging.getLogger(__name__)


def startup_actions() -> None:
    """
    Perform necessary startup actions for the TEA-Tool.

    This function needs to be called at the beginning of the program to ensure
    that all required initializations and configurations are done.
    """
    # Set the environment path
    tea_root = Path(__file__).resolve().parent.parent.parent
    dotenv_path = tea_root / ".env"
    set_key(dotenv_path=dotenv_path, key_to_set="TEA_ROOT", value_to_set=str(tea_root))
    
    # Load variables from the .env file into the environment
    load_dotenv(dotenv_path=dotenv_path)

    # Clear existing handlers (useful in testing)
    logging.root.handlers.clear()

    # Set or retrieve log path
    log_path = os.getenv("LOG_PATH")
    if not log_path:
        log_path = str(tea_root / ".tea.log")
        set_key(dotenv_path=dotenv_path, key_to_set="LOG_PATH", value_to_set=log_path)
    
    # Configure logging
    log_path = Path(log_path)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.FileHandler(log_path)],
    )

    # Check the DB-path and set to default if not set
    db_path = os.getenv("EXPOSURE_DB_PATH")
    if not db_path:
        db_path = str(tea_root / ".exposure.sqlite")
        set_key(dotenv_path=dotenv_path, key_to_set="EXPOSURE_DB_PATH", value_to_set=db_path)

    # Check the schedule path and set to default if not set
    schedule_path = os.getenv("SCHEDULE_PATH")
    if not schedule_path:
        schedule_path = str(tea_root / "schedule.json")
        set_key(dotenv_path=dotenv_path, key_to_set="SCHEDULE_PATH", value_to_set=schedule_path)
