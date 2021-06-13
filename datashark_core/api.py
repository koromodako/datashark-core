"""APi-related helpers
"""
from enum import Enum
from uuid import uuid4, UUID
from pathlib import Path
from typing import Union

class Object(dict):
    """
    Keeps track of an artefact to be processed
    """
    def __init__(
        self,
        parent: Union[str, UUID],
        filepath: Union[str, Path]
    ):
        super().__init__()
        self['uuid'] = str(uuid4())
        self['parent'] = str(parent)
        self['filepath'] = Path(filepath)

    @property
    def uuid(self) -> str:
        """Unique Identifier for this object"""
        return self['uuid']

    @property
    def parent(self) -> str:
        """Unique Identifier for this object"""
        return self['parent']

    @property
    def filepath(self) -> Path:
        """Filepath of the object to be processed"""
        return self['filepath']

class Status(Enum):
    """
    Overall processing result:
        - "success" means that the plugin produced everything as intented
        - "partial" means that the plugin encountered non fatal errors and might
          have produced partial results, manual review is advised.
        - "failure" means that the plugin failed to process given object, manual
          review is the only solution.
    """
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILURE = "failure"

class Result(dict):
    """
    Keeps track of plugin P processing result of artefact A
    """
    def __init__(
        self,
        plugin: str,
        obj: Object,
        status: Status
    ):
        super().__init__()
        self['plugin'] = plugin
        self['object'] = obj
        self['status'] = status

    @property
    def plugin(self) -> str:
        """Name of the plugin producing this result"""
        return self['plugin']

    @property
    def object(self) -> Object:
        """Processed object"""
        return self['object']

    @property
    def status(self) -> Status:
        """Overall status of processed object"""
        return self['status']
