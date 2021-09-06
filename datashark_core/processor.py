'''Processor-related helpers
'''
from abc import ABCMeta, abstractmethod
from uuid import uuid4
from time import time, gmtime, strftime
from typing import List, Tuple, Optional
from pathlib import Path
from .config import DatasharkConfiguration
from .logging import LOGGING_MANAGER
from .model.api import Processor, ProcessorResult, ProcessorArgument
from .model.database.helper import create_database_session


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
    async def _run(
        self, filepath: Path, arguments: List[ProcessorArgument]
    ) -> Tuple[bool, Optional[str]]:
        """
        Classes implementing ProcessorInterface must implement this method

        This method shall perform processor tasks, for instance:

        1. Invoke tool as an asynchronous subprocess
        2. Parse subprocess output
        3. Insert relevant objects (Artifact, Event and Property) in the DB
        4. Perform cleanup

        This method shall return a Tuple[status: bool, details: Optional[str]]
        """

    async def run(
        self, filepath: Path, arguments: List[ProcessorArgument]
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
        status, details = await self._run(filepath, arguments)
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
