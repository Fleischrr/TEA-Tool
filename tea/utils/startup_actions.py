"""Initialization and configuration for the TEA-Tool."""

import logging
from pathlib import Path

from dotenv import load_dotenv, set_key

from tea import utils

logger = logging.getLogger(__name__)


def startup_actions() -> None:
    """
    Perform necessary startup actions for the TEA-Tool.

    This function needs to be called at the beginning of the program to ensure
    that all required initializations and configurations are done.
    """
    # Set the TEA environment path
    tea_root = Path(__file__).resolve().parent.parent.parent
    dotenv_path = tea_root / ".env"
    set_key(dotenv_path=dotenv_path, key_to_set="TEA_ROOT", value_to_set=str(tea_root))
    
    # Load variables from the .env file into the environment
    load_dotenv(dotenv_path=dotenv_path)

    # Clear existing handlers (useful in testing) and set log path
    logging.root.handlers.clear()
    log_path = utils.set_log_path()
    
    # Configure logging  
    if log_path is not None:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[logging.FileHandler(log_path)],
        )

    # Log initialization details
    logger.info("Logging initialized.")
    logger.debug(f"TEA root: {tea_root}")
    logger.debug(f"Log path: {log_path}")

    # Set paths based on configuration or defaults 
    utils.set_db_path()
    utils.set_schedule_path()
    logger.debug("Configuratio paths set.")
