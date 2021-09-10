'''Processor-related helpers
'''
from abc import ABCMeta, abstractmethod
from uuid import uuid4
from time import time, gmtime, strftime
from typing import List, Dict, Optional
from pathlib import Path
from asyncio import create_subprocess_exec
from .config import (
    DatasharkConfiguration,
    DatasharkConfigurationError,
)
from .logging import LOGGING_MANAGER
from .model.api import Kind, Processor, ProcessorResult, ProcessorArgument
from .filesystem import prepend_workdir
from .model.database.helper import create_database_session


class ProcessorError(Exception):
    """Raised from processor _run() method"""


class ProcessorInterface(metaclass=ABCMeta):
    """Processor generic interface"""

    def __init__(self, config: DatasharkConfiguration, engine):
        self._uid = str(uuid4())
        self._config = config
        self._logger = LOGGING_MANAGER.get_logger(self.name)
        self._engine = engine
        self._session = None

    def __enter__(self):
        self._session = create_database_session(self._engine)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.close()
        self._session = None

    @classmethod
    def name(cls):
        """Processor's name"""
        return getattr(cls, 'NAME')

    @classmethod
    def processor(cls) -> Processor:
        """Processor's name"""
        return Processor.build(
            {
                'name': cls.name(),
                'system': getattr(cls, 'SYSTEM'),
                'arguments': getattr(cls, 'ARGUMENTS'),
                'description': getattr(cls, 'DESCRIPTION'),
            }
        )

    @property
    def uid(self):
        """Processor instance's uuid"""
        return self._uid

    @property
    def logger(self):
        """Processor instance's logger"""
        return self._logger

    @property
    def config(self):
        """Datashark configuration"""
        return self._config

    @property
    def session(self):
        """Processor instance's database session"""
        return self._session

    @abstractmethod
    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """
        Classes implementing ProcessorInterface must implement this method

        This method shall perform processor tasks, for instance:

        1. Invoke tool as an asynchronous subprocess
        2. Parse subprocess output
        3. Insert relevant objects (Artifact, Event and Property) in the DB
        4. Perform cleanup

        This method can raise Processor error to notify that an error occured
        """

    async def run(
        self, arguments: Dict[str, ProcessorArgument]
    ) -> ProcessorResult:
        """
        Wrapper method for _run() adding duration information and
        building ProcessorResult instance
        """
        start = time()
        start_time = strftime("%Y-%m-%dT%H:%M:%S+00:00", gmtime(start))
        self._logger.info(
            "%s#%s starting at %s", self.name(), self.uid, start_time
        )
        status = False
        details = None
        try:
            status, details = await self._run(arguments)
        except ProcessorError as err:
            details = str(err)
        except DatasharkConfigurationError:
            details = 'agent-side configuration file is invalid'
        except:
            details = 'unexpected exception, see agent-side event logs'
            self._logger.exception(
                "an unexpected exception was raised by processor: %s",
                self.__class__.__name__,
            )
        stop = time()
        stop_time = strftime("%Y-%m-%dT%H:%M:%S+00:00", gmtime(stop))
        duration = stop - start
        self._logger.info(
            "%s#%s stopping at %s (duration %d seconds)",
            self.name(),
            self.uid,
            stop_time,
            duration,
        )
        return ProcessorResult(
            status=status, duration=duration, details=details
        )

    async def _start_subprocess(
        self,
        prog_config_key: str,
        base_args: List[str],
        arg_option_map: Dict[str, Optional[str]],
        arguments: Dict[str, ProcessorArgument],
        /,
        **kwargs,
    ):
        # retrieve workdir and check access to it
        workdir = self.config.get('datashark.agent.workdir', type=Path)
        if not workdir.is_dir():
            raise ProcessorError("agent-side workdir not found!")
        # find program in configuration and determine if it exists
        program = self.config.get(prog_config_key, type=Path)
        if not program.is_file():
            raise ProcessorError("agent-side program not found!")
        program = str(program)
        # build program arguments
        for arg_name, cmd_option in arg_option_map:
            proc_arg = arguments.get(arg_name)
            value = proc_arg.get_value()
            # skip if no value
            if value is None:
                continue
            # prepend workdir if argument is path
            if proc_arg.kind == Kind.PATH:
                value = prepend_workdir(workdir, value)
            # if not positional argument, prepend optional argument value
            # with optional argument name
            if cmd_option:
                base_args.append(cmd_option)
            # append value to process arguments
            base_args.append(value)
        # start subprocess
        self._logger.info("exec: %s -> %s", program, base_args)
        return await create_subprocess_exec(program, base_args, **kwargs)
