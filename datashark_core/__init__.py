"""HTK Core
"""
from .__version__ import version, version_tuple
from .logging import LOGGING_MANAGER

NAME = 'core'
LOGGER = LOGGING_MANAGER.get_logger(NAME)
