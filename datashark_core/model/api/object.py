"""Datashark API objects
"""
from os import cpu_count
from abc import ABCMeta, abstractmethod
from enum import Enum
from typing import List, Dict, Optional
from pathlib import Path
from textwrap import dedent, indent as indent_
from platform import (
    node,
    system,
    machine,
    platform,
    processor,
    python_version,
)
from dataclasses import dataclass
from ... import LOGGER
from ...logging import cprint, COLORED

INDENT_UNIT = 4 * ' '


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
    Kind.BOOL: lambda val: val.lower() not in ['false', 'no', '0'],
    Kind.PATH: Path,
    Kind.FLOAT: float,
}

KIND_COLOR_MAP = {
    Kind.INT: 'slate_blue1',
    Kind.STR: 'green',
    Kind.BOOL: 'slate_blue1',
    Kind.PATH: 'dodger_blue1',
    Kind.FLOAT: 'slate_blue1',
}


class System(Enum):
    """Types of systems"""

    LINUX = 'Linux'
    DARWIN = 'Darwin'
    WINDOWS = 'Windows'
    INDEPENDENT = 'Independent'


COMPATIBLE_SYSTEMS = [System(system()), System.INDEPENDENT]


class APIObjectInterface(metaclass=ABCMeta):
    """Abstract interface for objects exchanged through the API"""

    @classmethod
    @abstractmethod
    def build(cls, dct):
        """Build object from dict"""

    @abstractmethod
    def as_dict(self):
        """Convert object to dict"""

    def display(self, indent=""):
        """Display a human representation of the dict representation"""
        dct = self.as_dict()
        mkl = max([len(key) for key in dct.keys()])
        for key, value in dct.items():
            key = f'{key:>{mkl}}:'
            key = f'[b]{key}[/]' if COLORED else key
            cprint(f"{indent}{key} {value}")


@dataclass
class ProcessorArgument(APIObjectInterface):
    """Processor argument API object"""

    name: str
    kind: Kind
    value: Optional[str] = None
    required: bool = False
    description: Optional[str] = None

    @classmethod
    def build(cls, dct):
        """Build object from dict"""
        kwargs = {
            'name': dct['name'],
            'kind': Kind(dct['kind']),
            'value': dct.get('value'),
            'required': dct['required'],
        }
        description = dct.get('description')
        if description:
            kwargs['description'] = dedent(description.strip('\n'))
        return cls(**kwargs)

    def as_dict(self):
        """Convert object to dict"""
        dct = {
            'name': self.name,
            'kind': self.kind.value,
        }
        if self.value:
            dct['value'] = self.value
        dct['required'] = self.required
        if self.description:
            dct['description'] = self.description
        return dct

    def validate(self):
        """Determine if required attribute as a value"""
        return not self.required or self.value is not None

    def set_value(self, value):
        """Set the value converted to string"""
        self.value = str(value)

    def get_value(self):
        """Get typed argument value"""
        if self.value is None:
            return self.value
        kind_cls = KIND_CLASS_MAP[self.kind]
        return kind_cls(self.value)

    def get_docstring(self):
        """Return argument docstring"""
        name = self.name
        kind = self.kind.value
        argument = f"{name}:{kind}"
        argument = f"[b]{argument}[/]" if COLORED else argument
        value = f'"{self.value}"' if self.kind == Kind.STR else self.value
        if COLORED:
            color = KIND_COLOR_MAP[self.kind]
            value = f"[{color}]{value}[/]"
        default = f" = {value}" if self.value is not None else ""
        required = "[red](required)[/]" if COLORED else "(required)"
        required = f" {required}" if self.required else ""
        description = indent_(self.description, INDENT_UNIT)
        description = f"[white]{description}[/]" if COLORED else description
        return f"{argument}{default}{required}\n{description}"


@dataclass
class Processor(APIObjectInterface):
    """Processor API object"""

    name: str
    system: System
    arguments: Dict[str, ProcessorArgument]
    description: Optional[str]

    @classmethod
    def build(cls, dct):
        """Build object from dict"""
        arguments = [
            ProcessorArgument.build(proc_arg) for proc_arg in dct['arguments']
        ]
        kwargs = {
            'name': dct['name'],
            'system': System(dct['system']),
            'arguments': {proc_arg.name: proc_arg for proc_arg in arguments},
        }
        description = dct.get('description')
        if description:
            kwargs['description'] = dedent(description)
        return cls(**kwargs)

    def as_dict(self):
        """Convert object to dict"""
        dct = {
            'name': self.name,
            'system': self.system.value,
            'arguments': [
                proc_arg.as_dict() for proc_arg in self.arguments.values()
            ],
        }
        if self.description:
            dct['description'] = self.description
        return dct

    def get_arg(self, key):
        """ProcessorArgument matching key or None"""
        return self.arguments.get(key)

    def validate_arguments(self):
        """Validate processor arguments"""
        for proc_arg in self.arguments.values():
            if not proc_arg.validate():
                LOGGER.error(
                    "processor argument is required: %s", proc_arg.name
                )
                return False
        return True

    def get_docstring(self):
        """Return processor docstring"""
        name = self.name
        system_ = self.system.value
        title = f"{name} ({system_})"
        title = f"[b]{title}[/]" if COLORED else title
        description = self.description
        description = f"[white]{description}[/]" if COLORED else description
        intro = f"{title}\n{description}"
        arguments = [
            indent_(proc_arg.get_docstring(), INDENT_UNIT)
            for proc_arg in self.arguments.values()
        ]
        arguments = "\n\n".join(arguments)
        return f"{intro}\n{arguments}\n"


@dataclass
class ProcessorResult(APIObjectInterface):
    """Processing response"""

    status: bool
    duration: float
    details: Optional[str]

    @classmethod
    def build(cls, dct):
        """Build object from dict"""
        return cls(
            status=dct['status'],
            duration=dct['duration'],
            details=dct.get('details'),
        )

    def as_dict(self):
        """Convert object to dict"""
        dct = {
            'status': self.status,
            'duration': self.duration,
        }
        if self.details:
            dct['details'] = self.details
        return dct


@dataclass
class AgentInfoResponse(APIObjectInterface):
    """Agent information response"""

    node: str = node()
    system: str = system()
    machine: str = machine()
    platform: str = platform()
    processor: str = processor()
    cpu_count: int = cpu_count()
    python_version: str = python_version()

    @classmethod
    def build(cls, dct):
        """Build object from dict"""
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
        """Convert object to dict"""
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
class ProcessorsRequest(APIObjectInterface):
    """Processors request"""

    search: Optional[str] = None

    @classmethod
    def build(cls, dct):
        """Build object from dict"""
        return cls(search=dct.get('search'))

    def as_dict(self):
        """Convert object to dict"""
        dct = {}
        if self.search:
            dct['search'] = self.search
        return dct


@dataclass
class ProcessorsResponse(APIObjectInterface):
    """Processors response"""

    processors: List[Processor]

    @classmethod
    def build(cls, dct):
        """Build object from dict"""
        return cls(
            processors=[Processor.build(proc) for proc in dct['processors']]
        )

    def as_dict(self):
        """Convert object to dict"""
        return {'processors': [proc.as_dict() for proc in self.processors]}


@dataclass
class ProcessingRequest(APIObjectInterface):
    """Processing request"""

    processor: Processor

    @classmethod
    def build(cls, dct):
        """Build object from dict"""
        return cls(processor=Processor.build(dct['processor']))

    def as_dict(self):
        """Convert object to dict"""
        return {'processor': self.processor.as_dict()}


@dataclass
class ProcessingResponse(APIObjectInterface):
    """Processing response"""

    result: ProcessorResult

    @classmethod
    def build(cls, dct):
        """Build object from dict"""
        return cls(result=ProcessorResult.build(dct['result']))

    def as_dict(self):
        """Convert object to dict"""
        return {'result': self.result.as_dict()}
