"""Logging-related helpers
"""
from logging import basicConfig, getLogger


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


basicConfig(format='%(message)s', datefmt='[%Y-%m-%dT%H:%M:%S]', level='DEBUG')
LOGGING_MANAGER = LoggingManager('datashark')
