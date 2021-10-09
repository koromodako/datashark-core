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

    def _log_info(self, fmt, *args):
        """Log processor information"""
        fmt = f"%s#%s: {fmt}"
        self._logger.info(fmt, self.name(), self.uid, *args)

    def _log_error(self, fmt, *args):
        """Log processor error"""
        fmt = f"%s#%s: {fmt}"
        self._logger.error(fmt, self.name(), self.uid, *args)

    def _log_exception(self, fmt, *args):
        """Log processor exception"""
        fmt = f"%s#%s: {fmt}"
        self._logger.exception(fmt, self.name(), self.uid, *args)

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
        # memorize start time
        start = time()
        start_time = strftime("%Y-%m-%dT%H:%M:%S+00:00", gmtime(start))
        # log information
        self._log_info("starting: %s", start_time)
        for arg_name, proc_arg in arguments.items():
            self._log_info("argument: %s:%s", arg_name, proc_arg.get_value())
        # start processing
        status = False
        details = None
        try:
            await self._run(arguments)
            status = True
        except (ProcessorError, ValueError) as err:
            details = str(err)
            self._log_error("error: %s", details)
        except DatasharkConfigurationError:
            details = 'agent-side configuration file is invalid'
            self._log_error("error: %s", details)
        except:
            details = 'unexpected exception, see agent-side event logs'
            self._log_exception("exception:")
        # compute duration
        stop = time()
        stop_time = strftime("%Y-%m-%dT%H:%M:%S+00:00", gmtime(stop))
        duration = stop - start
        # log information
        self._log_info(
            "stopped: %s (duration %d seconds)", stop_time, duration
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
                value = prepend_workdir(self.config, value)
            # if not positional argument, prepend optional argument value
            # with optional argument name
            if cmd_option:
                # special processing for optional boolean
                if proc_arg.kind == Kind.BOOL and not value:
                    continue
                # add cmd_option part e.g. "--example" in "--exemple value"
                base_args.append(cmd_option)
                # special processing for optional boolean
                if proc_arg.kind == Kind.BOOL:
                    continue
            # append cmd option value to process arguments
            # e.g. "value" in "--exemple value" or just "value" for positional
            # arguments
            base_args.append(value)
        # start subprocess
        return await create_subprocess_exec(program, *base_args, **kwargs)

    async def _handle_communicating_process(self, proc):
        """Generic handling of a regular communicating process"""
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            if not stderr:
                stderr = (
                    "called program exited with code {proc.returncode} and "
                    "did not provide any information on stderr, thank the "
                    "developper for that."
                )
            raise ProcessorError(stderr)
        return stdout, stderr
