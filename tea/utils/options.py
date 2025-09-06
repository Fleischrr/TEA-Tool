"""Utility function that configures the options for the TEA Tool."""

import logging
import os
from pathlib import Path

from dotenv import get_key, set_key
from rich.console import Console

from tea import utils

logger = logging.getLogger(__name__)

console = Console()

TEA_ROOT = Path(os.getenv("TEA_ROOT", os.getcwd())) 
DOTENV_PATH = TEA_ROOT / ".env"


def set_log_path(log_path: str | None = None) -> Path | None:
    """
    Set the log path in the environment.

    :param log_path: The path to set.
    :type log_path: str
    :return: The status for the action.
    :rtype: bool
    """
    if not log_path: 
        # Retrieve log path from env 
        log_path_env = get_key(dotenv_path=DOTENV_PATH, key_to_get="LOG_PATH")

        # Set default log path if env path is empty
        log_path = str(TEA_ROOT / ".tea.log") if log_path_env is None else log_path_env
            
    
    # Test and set the log path
    try:
        if not utils.verify_file_path(log_path):
            return None

        set_key(
            dotenv_path=DOTENV_PATH, key_to_set="LOG_PATH", value_to_set=log_path
        )
        logger.info("Log path set successfully.")

        return Path(log_path)
    
    except Exception as e:
        logger.error(f"Failed to set given log path with error: {e}")
        return None
    

def set_db_path(db_path: str | None = None) -> Path | None:
    """
    Set the exposure database path in the environment.

    :param db_path: The path to set.
    :type db_path: str
    :return: The status for the action.
    :rtype: bool
    """
    if not db_path: 
        # Retrieve db path from env
        db_path_env = get_key(dotenv_path=DOTENV_PATH, key_to_get="EXPOSURE_DB_PATH")

        # Set default db path if env path is empty
        db_path = str(TEA_ROOT / ".exposure.sqlite") if db_path_env is None else db_path_env
    
    # Test and set the db path
    try:

        if not utils.verify_file_path(db_path):
            return None

        set_key(
            dotenv_path=DOTENV_PATH, key_to_set="EXPOSURE_DB_PATH", value_to_set=db_path
        )
        logger.info("Exposure database path set successfully.")

        return Path(db_path)
    
    except Exception as e:
        logger.error(f"Failed to set given exposure database path with error: {e}")
        return None


def set_schedule_path(schedule_path: str | None = None) -> Path | None:
    """
    Set the schedule path in the environment.

    :param schedule_path: The path to set.
    :type schedule_path: str
    :return: The status for the action.
    :rtype: bool
    """
    if not schedule_path: 
        # Retrieve db path from env
        schedule_path_env = get_key(dotenv_path=DOTENV_PATH, key_to_get="SCHEDULE_PATH")

        # Set default db path if env path is empty
        if schedule_path_env is None:
            schedule_path = str(TEA_ROOT / "schedule.json")
        else: 
            schedule_path = schedule_path_env
    
    # Test and set the db path
    try:

        if not utils.verify_file_path(schedule_path):
            return None

        set_key(
            dotenv_path=DOTENV_PATH, key_to_set="SCHEDULE_PATH", value_to_set=schedule_path
        )
        logger.info("Schedule path set successfully.")

        return Path(schedule_path)
    
    except Exception as e:
        logger.error(f"Failed to set given schedule path with error: {e}")
        return None