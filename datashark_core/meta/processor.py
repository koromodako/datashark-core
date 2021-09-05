"""Plugin metaclass
"""
import re
from abc import ABCMeta
from typing import Iterator
from importlib.metadata import entry_points
from .. import LOGGER
from ..processor import ProcessorInterface
from ..model.api import System, COMPATIBLE_SYSTEMS


NAME_RE = re.compile(r'\w+')


class ProcessorMeta(ABCMeta):
    """Datashark processor metaclass"""

    MANDATORY = {
        'NAME',
        'SYSTEM',
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
                f"processor error: {name} (undefined mandatory attribute: {mandatory})"
            )
        # perform system check
        ns_system = namespace['SYSTEM']
        if not isinstance(ns_system, System):
            raise ValueError(
                f"processor error: {name} (SYSTEM attribute must be a System instance)"
            )
        if ns_system not in COMPATIBLE_SYSTEMS:
            LOGGER.warning(
                "processor skipped: %s (not supported by current system)",
                name,
            )
            return ncls
        # perform name check
        ns_name = namespace['NAME']
        if not NAME_RE.fullmatch(ns_name):
            raise ValueError(
                f"processor error: {name} (NAME attribute must validate regexp: {NAME_RE.pattern})"
            )
        if ns_name in ProcessorMeta.REGISTERED:
            raise ValueError(
                f"processor error: {name} (NAME attribute already registered by another processor)"
            )
        ProcessorMeta.REGISTERED[ns_name] = ncls
        LOGGER.info("processor registered: %s", ns_name)
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


def enumerate_processor_classes() -> Iterator[ProcessorInterface]:
    """Enumerate loaded processors"""
    for processor_class in ProcessorMeta.REGISTERED.values():
        yield processor_class


def get_processor_class(name: str) -> ProcessorInterface:
    """Retrieve processor class from loaded processors"""
    processor_class = ProcessorMeta.REGISTERED.get(name, None)
    if not processor_class:
        LOGGER.warning("failed to retrieve processor: %s", name)
    return processor_class
