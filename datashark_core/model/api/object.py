"""Datashark API objects
"""
from enum import Enum
from typing import List, Optional
from pathlib import Path
from textwrap import dedent
from dataclasses import dataclass

class Kind(Enum):
    """Types of argument kind"""
    INT = 'int'
    STR = 'str'
    BOOL = 'bool'
    PATH = 'path'
    FLOAT = 'float'


KIND_CLASS_MAP = {
    Kind.INT: int,
    Kind.STR: str,
    Kind.BOOL: bool,
    Kind.PATH: Path,
    Kind.FLOAT: float,
}


class Platform(Enum):
    """Types of platform"""
    LINUX = 'Linux'
    DARWIN = 'Darwin'
    WINDOWS = 'Windows'
    INDEPENDENT = 'Independent'


@dataclass
class ProcessorArgument:
    """Processor argument API object"""
    name: str
    kind: Kind
    value: Optional[str] = None
    description: Optional[str] = None

    @classmethod
    def build(cls, dct):
        """Build from dict"""
        kwargs = {
            'name': dct['name'],
            'kind': Kind(dct['kind']),
            'value': dct.get('value'),
        }
        description = dct.get('description')
        if description:
            kwargs['description'] = dedent(description)
        return cls(**kwargs)

    def get_value(self):
        """Get typed argument value"""
        kind_cls = KIND_CLASS_MAP[self.kind]
        return kind_cls(self.value)

    def as_dict(self):
        """Convert to dict"""
        dct = {
            'name': self.name,
            'kind': self.kind.value,
        }
        if self.value:
            dct['value'] = self.value
        if self.description:
            dct['description'] = self.description
        return dct


@dataclass
class Processor:
    """Processor API object"""
    name: str
    platform: Platform
    arguments: List[ProcessorArgument]
    description: Optional[str]

    @classmethod
    def build(cls, dct):
        """Build from dict"""
        kwargs = {
            'name': dct['name'],
            'platform': Platform(dct['platform']),
            'arguments': [
                ProcessorArgument.build(proc_arg)
                for proc_arg in dct['arguments']
            ],
        }
        description = dct.get('description')
        if description:
            kwargs['description'] = dedent(description)
        return cls(**kwargs)

    def as_dict(self):
        """Convert to dict"""
        dct = {
            'name': self.name,
            'platform': self.platform.value,
            'arguments': [proc_arg.as_dict() for proc_arg in self.arguments],
        }
        if self.description:
            dct['description'] = self.description
        return dct


@dataclass
class ProcessorResult:
    """Processing response"""
    status: bool
    duration: float
    details: Optional[str]

    @classmethod
    def build(cls, dct):
        """Build from dict"""
        return cls(
            status=dct['status'],
            duration=dct['duration'],
            details=dct.get('details'),
        )

    def as_dict(self):
        """Convert to dict"""
        dct = {
            'status': self.status,
            'duration': self.duration,
        }
        if self.details:
            dct['details'] = self.details
        return dct


@dataclass
class ProcessorsRequest:
    """Processors request"""
    search: Optional[str] = None

    @classmethod
    def build(cls, dct):
        """Build from dict"""
        return cls(search=dct.get('search'))

    def as_dict(self):
        """Convert to dict"""
        dct = {}
        if self.search:
            dct['search'] = self.search
        return dct


@dataclass
class ProcessorsResponse:
    """Processors response"""
    processors: List[Processor]

    @classmethod
    def build(cls, dct):
        """Build from dict"""
        return cls(
            processors=[Processor.build(proc) for proc in dct['processors']]
        )

    def as_dict(self):
        """Convert to dict"""
        return {'processors': [proc.as_dict() for proc in self.processors]}


@dataclass
class ProcessingRequest:
    """Processing request"""
    filepath: Path
    processor: Processor

    @classmethod
    def build(cls, dct):
        """Build from dict"""
        return cls(
            filepath=Path(dct['filepath']),
            processor=Processor.build(dct['processor']),
        )

    def as_dict(self):
        """Convert to dict"""
        return {
            'filepath': str(self.filepath),
            'processor': self.processor.as_dict(),
        }


@dataclass
class ProcessingResponse:
    """Processing response"""
    status: bool
    details: str

    @classmethod
    def build(cls, dct):
        """Build from dict"""
        return cls(
            status=dct['status'],
            details=dct['details'],
        )

    def as_dict(self):
        """Convert to dict"""
        return {
            'status': self.status,
            'details': self.details,
        }
