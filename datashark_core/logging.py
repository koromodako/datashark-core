"""Logging-related helpers
"""
from logging import basicConfig, getLogger
from logging.handlers import RotatingFileHandler
from rich.console import Console
from rich.logging import RichHandler

CONSOLE = Console(highlight=False)
COLORED = True


def cwidth():
    """Console width"""
    return CONSOLE.width


def cprint(*args, **kwargs):
    """Print function"""
    CONSOLE.print(*args, **kwargs)


def build_rich_handler():
    rich_handler = RichHandler(
        omit_repeated_times=False,
        rich_tracebacks=True,
        console=Console(stderr=True, highlight=False),
        markup=False,
    )
    rich_handler.setLevel('DEBUG')
    return rich_handler


def build_rotating_file_handler(logpath):
    handler = RotatingFileHandler(logpath, maxBytes=16384000, backupCount=4)
    return handler


def setup_logging(log_to=None):
    datefmt = '[%Y-%m-%dT%H:%M:%S]'
    if log_to:
        msgfmt = '%(asctime)s(%(levelname)8s) %(message)s'
        handler = build_rotating_file_handler(log_to)
    else:
        msgfmt = '%(message)s'
        handler = build_rich_handler()
    basicConfig(
        format=msgfmt, datefmt=datefmt, level='DEBUG', handlers=[handler]
    )


class LoggingManager:
    """Logging manager"""

    def __init__(self, root):
        self._root = root
        self._loggers = {}
        self._global_level = 'INFO'

    def _get_path(self, name=None):
        if not name:
            return self._root
        return f"{self._root}.{name}"

    def _reconfigure_loggers(self):
        for _, logger in self._loggers.items():
            logger.setLevel(self._global_level)

    def set_debug(self, enabled):
        """Enable debug for all loggers"""
        self._global_level = 'DEBUG' if enabled else 'INFO'
        self._reconfigure_loggers()

    def get_logger(self, name=None):
        """Retrieve or register a new logger"""
        path = self._get_path(name)
        logger = self._loggers.get(path)
        if not logger:
            logger = getLogger(path)
            logger.setLevel(self._global_level)
            self._loggers[path] = logger
        return logger


LOGGING_MANAGER = LoggingManager('datashark')
