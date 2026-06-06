# app/logging_config.py
"""Central logging configuration.

Log level is controlled by the LOG_LEVEL env var (default INFO). Noisy
third-party loggers are quieted so application logs stay readable.
"""
import logging
import os
import sys

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

logging.basicConfig(
    level=LOG_LEVEL,
    format=_FORMAT,
    datefmt=_DATEFMT,
    handlers=[logging.StreamHandler(sys.stdout)],
)

# Tame noisy third-party loggers (e.g. the passlib/bcrypt version warning,
# httpx request lines) so they don't drown out application logs.
logging.getLogger("passlib").setLevel(logging.ERROR)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# Shared application logger. Import this, or use get_logger("module") for a
# child logger that shows the module name in the output.
logger = logging.getLogger("app")
logger.setLevel(LOG_LEVEL)


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger, e.g. get_logger('gate') -> 'app.gate'."""
    return logging.getLogger(f"app.{name}")
