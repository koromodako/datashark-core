"""Database-related helpers
"""
from typing import Union
from pathlib import Path
from yarl import URL
from redis import Redis
from sqlalchemy.orm import Session
from sqlalchemy.engine import create_engine
from .. import LOGGER
from ..filesystem import ensure_parent_dir

CORE_REDIS = Redis()


def generic_init_db_session(
    engine_url: URL, lock: str, base_cls
) -> Union[Session, Redis]:
    LOGGER.info("waiting for init_database_session lock...")
    with CORE_REDIS.lock(lock, blocking_timeout=None):
        # ugly fix for sqlite file-backed database, yeah i'm not proud...
        if engine_url.scheme == 'sqlite':
            filepath = Path(engine_url.path)
            ensure_parent_dir(filepath)
            engine_url = f'sqlite:///{engine_url.path}'
        elif engine_url.scheme == 'redis':
            return Redis(host=engine_url.host, port=engine_url.port)
        else:
            engine_url = engine_url.human_repr()
        LOGGER.info("lock acquired, creating engine...")
        engine = create_engine(engine_url)
        LOGGER.info("creating database schema if necessary...")
        base_cls.metadata.create_all(engine)
        LOGGER.info("creating a new session...")
        return Session(engine)
