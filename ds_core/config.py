"""Configuration-related functions
"""
from pathlib import Path
from ruamel.yaml import safe_load
from . import LOGGER

DEFAULT_CONFIG_PATH = Path.home() / '.config' / 'datashark' / 'datashark.yml'


class DSConfigurationError(Exception):
    """Error raised when a configuration error occurs"""


class DSConfiguration:
    """Configuration object"""

    def __init__(self, filepath: Path):
        if filepath.is_file():
            data = safe_load(filepath.read_text())
        else:
            LOGGER.error("%s is not a valid filepath!", filepath)
            data = None
        self._data = data

    @property
    def is_valid(self):
        """Determine if configuration is valid"""
        return self._data is not None

    def get(self, *path, **kwargs):
        """Retrieve configuration value"""
        obj = self._data
        components = [comp.split('.') for comp in path]
        for item in components:
            obj = obj.get(item, None)
            # value not found
            if obj is None:
                msg = ("configuration value not found: %s", '.'.join(path))
                try:
                    default = kwargs['default']
                    LOGGER.warning(*msg)
                    return default
                except KeyError as exc:
                    LOGGER.critical(*msg)
                    raise DSConfigurationError(
                        "configuration file is missing a mandatory value!"
                    ) from exc
        # value found
        type_cls = kwargs.get('type', None)
        if type_cls:
            return type_cls(obj)
        return obj
