"""Datashark API objects
"""
from os import cpu_count
from enum import Enum
from typing import List, Optional
from pathlib import Path
from textwrap import dedent
from platform import (
    node,
    system,
    machine,
    platform,
    processor,
    python_version,
)
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


class System(Enum):
    """Types of systems"""

    LINUX = 'Linux'
    DARWIN = 'Darwin'
    WINDOWS = 'Windows'
    INDEPENDENT = 'Independent'


COMPATIBLE_SYSTEMS = [System(system()), System.INDEPENDENT]


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
    system: System
    arguments: List[ProcessorArgument]
    description: Optional[str]

    @classmethod
    def build(cls, dct):
        """Build from dict"""
        kwargs = {
            'name': dct['name'],
            'system': System(dct['system']),
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
            'system': self.system.value,
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
class AgentInfoResponse:
    """Agent information response"""

    node: str
    system: str
    machine: str
    platform: str
    processor: str
    cpu_count: int
    python_version: str

    @classmethod
    def build(cls, dct):
        """Build from dict"""
        return cls(
            node=dct.get('node', node()),
            system=dct.get('system', system()),
            machine=dct.get('machine', machine()),
            platform=dct.get('platform', platform()),
            processor=dct.get('processor', processor()),
            cpu_count=dct.get('cpu_count', cpu_count()),
            python_version=dct.get('python_version', python_version()),
        )

    def as_dict(self):
        """Convert to dict"""
        return {
            'node': self.node,
            'system': self.system,
            'machine': self.machine,
            'platform': self.platform,
            'processor': self.processor,
            'cpu_count': self.cpu_count,
            'python_version': self.python_version,
        }


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

    result: ProcessorResult

    @classmethod
    def build(cls, dct):
        """Build from dict"""
        return cls(processor_result=dct['result'])

    def as_dict(self):
        """Convert to dict"""
        return {
            'result': self.result.as_dict(),
        }
