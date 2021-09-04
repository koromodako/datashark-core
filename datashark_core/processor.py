'''Processor-related helpers
'''
from abc import ABCMeta, abstractmethod
from time import time, gmtime
from typing import List, Tuple, Optional
from asyncio import Lock
from .config import DatasharkConfiguration
from .logging import LOGGING_MANAGER
from .model.api import Processor, ProcessorResult, ProcessorArgument
from .model.database.helper import create_database_session


class ProcessorInterface(metaclass=ABCMeta):
    """Processor generic interface"""

    def __init__(self, config: DatasharkConfiguration, engine):
        self._config = config
        self._logger = LOGGING_MANAGER.get_logger(self.name)
        self._engine = engine
        self._session = None
        self._counter = 0
        self._counter_lock = Lock()

    def __enter__(self):
        self._session = create_database_session(self._engine)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.close()
        self._session = None

    @property
    def name(self):
        """Processor's name"""
        return getattr(self, 'NAME')

    @property
    def logger(self):
        """Processor's logger"""
        return self._logger

    @property
    def config(self):
        """Datashark configuration"""
        return self._config

    @property
    def session(self):
        """Plugin's database session"""
        return self._session

    @property
    def processor(self) -> Processor:
        """Processor's name"""
        return Processor.build({
            'name': self.name,
            'arguments': getattr(self, 'ARGUMENTS'),
            'description': getattr(self, 'DESCRIPTION'),
        })

    @abstractmethod
    async def _run(self, arguments: List[ProcessorArgument]) -> Tuple[bool, Optional[str]]:
        """
        Classes implementing ProcessorInterface must implement this method

        This method shall perform processor tasks, for instance:

        1. Invoke tool as an asynchronous subprocess
        2. Parse subprocess output
        3. Insert relevant objects (Artifact, Event and Property) in the DB
        4. Perform cleanup

        This method shall return a Tuple[status: bool, details: Optional[str]]
        """

    async def run(self, arguments: List[ProcessorArgument]) -> ProcessorResult:
        """
        Wrapper method for _run() adding duration information and
        building ProcessorResult instance
        """
        async with self._counter_lock:
            counter = self._counter
            self._counter += 1
        start = time()
        self._logger.info(
            "%s#%08d starting at %s", self.name, counter, gmtime(start)
        )
        status, details = await self._run(arguments)
        stop = time()
        duration = stop - start
        self._logger.info(
            "%s#%08d stopping at %s (duration %d seconds)",
            self.name,
            counter,
            gmtime(stop),
            duration,
        )
        return ProcessorResult.build({
            'status': status,
            'duration': duration,
            'details': details,
        })
