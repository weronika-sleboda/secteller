"""
Contains logger settings
"""
import logging
from enum import Enum

logger = logging.getLogger("app")

class LogType(Enum):
    """Type of logs to be printed"""
    ERROR = 1
    INFO = 2


def log(log_type: LogType, message: str):
    """ Selects appropriate logger and prints the message to the console"""
    output = f"[SECTELLER] {message}"
    match log_type:
        case LogType.ERROR:
            logger.error(output)
        case LogType.INFO:
            logger.info(output)
