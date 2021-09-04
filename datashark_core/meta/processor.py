"""Plugin metaclass
"""
import re
from abc import ABCMeta
from importlib.metadata import entry_points
from .. import LOGGER


NAME_RE = re.compile(r'\w+')


class ProcessorMeta(ABCMeta):
    """Datashark plugin metaclass"""

    MANDATORY = {
        'NAME',
        'ARGUMENTS',
        'DESCRIPTION',
    }
    REGISTERED = {}

    def __new__(cls, name, bases, namespace, /, **kwargs):
        # build new class
        ncls = super().__new__(cls, name, bases, namespace, **kwargs)
        # perform mandatory attributes check
        mandatory_attributes = ProcessorMeta.MANDATORY
        for mandatory in mandatory_attributes:
            if mandatory in namespace:
                continue
            raise NotImplementedError(
                f"class '{name}' shall define mandatory '{mandatory}'!"
            )
        # perform name check
        ns_name = namespace['NAME']
        if not NAME_RE.fullmatch(ns_name):
            raise ValueError(
                f"class '{name}' NAME attribute must validate regexp '{NAME_RE.pattern}'!"
            )
        if ns_name in ProcessorMeta.REGISTERED:
            raise ValueError(
                f"class '{name}' NAME already registered by another plugin!"
            )
        ProcessorMeta.REGISTERED[ns_name] = ncls
        LOGGER.info("plugin registered: %s", ns_name)
        # finally return new class
        return ncls


def load_processors() -> bool:
    """Dynamically load installed processors"""
    eps = entry_points()
    loaded = False
    for entry_point in eps.get('datashark_processors', []):
        loaded = True
        try:
            entry_point.load()
        except:
            LOGGER.exception("failed to load processor: %s", entry_point)
    return loaded
