"""Configuration-related functions
"""
from typing import Union
from pathlib import Path
from ruamel.yaml import safe_load
from . import LOGGER


class DatasharkConfigurationError(Exception):
    """Error raised when a configuration error occurs"""


class DatasharkConfiguration:
    """Configuration object"""

    def __init__(self, filepath: Union[Path, str]):
        filepath = Path(filepath)
        if not filepath.is_file():
            LOGGER.error("%s is not a valid filepath!", filepath)
            self._data = None
            return
        self._data = safe_load(filepath.read_text())

    @property
    def is_valid(self):
        """Determine if configuration is valid"""
        return self._data is not None

    def get(self, *path, **kwargs):
        """Retrieve configuration value"""
        obj = self._data
        components = []
        for comp in path:
            if '.' in comp:
                components += comp.split('.')
            else:
                components.append(comp)
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
                    raise DatasharkConfigurationError(
                        "configuration file is missing a mandatory value!"
                    ) from exc
        # value found
        type_cls = kwargs.get('type', None)
        if type_cls:
            return type_cls(obj)
        return obj


def override_arg(arg, config, config_key, default):
    """Select best argument based on given arguments"""
    if arg:
        return arg
    if config:
        config_val = config.get(config_key, default=None)
        if config_val:
            return config_val
    if callable(default):
        return default()
    return default
