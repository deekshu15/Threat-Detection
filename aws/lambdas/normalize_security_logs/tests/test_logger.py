import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(PROJECT_ROOT))

from utils.logger import get_logger


def test_get_logger_returns_a_logger_instance():
    """get_logger should return an actual Python logging.Logger object."""
    logger = get_logger(__name__)
    assert isinstance(logger, logging.Logger)


def test_logger_has_correct_name():
    """The logger's name should match what was passed in."""
    logger = get_logger(__name__)
    assert logger.name == __name__


def test_logger_has_at_least_one_handler():
    """A logger with no handlers silently produces no output anywhere - that's a bug."""
    logger = get_logger(__name__)
    assert len(logger.handlers) > 0, "Logger has no handlers - log messages would go nowhere"


def test_logger_methods_do_not_raise():
    """Calling all log levels should never crash, regardless of configuration."""
    logger = get_logger(__name__)
    logger.debug("Debug log")
    logger.info("Info log")
    logger.warning("Warning log")
    logger.error("Error log")
    logger.critical("Critical log")
    # If we reach this line, nothing above raised an exception - test passes.
    assert True