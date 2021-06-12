"""Configuration-related functions
"""
import sys
from ruamel.yaml import safe_load
from . import LOGGER
from .platform import CONFIG_PATH


class Config(dict):
    """Configuration object"""

    @classmethod
    def load(cls, filepath):
        """Build a Config instance from a file"""
        if not filepath.is_file():
            LOGGER.error("%s is not a valid filepath!", filepath)
            return None
        return cls(safe_load(filepath.read_text()))

    def get_(self, *path, **kwargs):
        """Retrieve configuration value"""
        value = self
        default = kwargs.get('default', None)
        for item in path:
            value = value.get(item, None)
            # value not found
            if value is None:
                LOGGER.warning(
                    "configuration value not found: %s", '.'.join(path)
                )
                return default
        # value found
        type_cls = kwargs.get('type', None)
        if type_cls:
            return type_cls(value)
        return value


if not CONFIG_PATH.parent.is_dir():
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
if not CONFIG_PATH.is_file():
    CONFIG_PATH.write_text(
        '\n'.join(
            [
                '#',
                '# Datashark configuration file',
                '#',
            ]
        )
    )
try:
    CONFIG = Config.load(CONFIG_PATH)
except:
    LOGGER.exception(
        "an exception occurred while loading configuration: %s", CONFIG_PATH
    )
    sys.exit(1)
