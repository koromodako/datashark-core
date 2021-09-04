"""Database-related helpers
"""
from yarl import URL
from sqlalchemy.orm import Session, create_engine
from ... import LOGGER
from ...config import DatasharkConfiguration
from .object import Base


def init_database_engine(config: DatasharkConfiguration):
    """
    Initialize database engine
    """
    engine_url = config.get('datashark.core.database.url', type=URL)
    LOGGER.info("creating database engine...")
    return create_engine(engine_url.human_repr())


def init_database_model(engine):
    """
    Initialize database model
    """
    LOGGER.info("creating database schema if necessary...")
    Base.metadata.create_all(engine)


def create_database_session(engine) -> Session:
    """
    Create a new database session
    """
    LOGGER.info("creating a new session...")
    return Session(engine)


def get_one(session: Session, obj_cls, **kwargs):
    """
    Retrieve exactly one object of obj_cls class from database or raise
    """
    return session.query(obj_cls).filter_by(**kwargs).one()


def get_or_create(session: Session, obj_cls, **kwargs):
    """
    Retrieve object from database or make a new one
    """
    obj = session.query(obj_cls).filter_by(**kwargs).one_or_none()
    if obj:
        return obj
    return obj_cls(**kwargs)


def enumerate_all(session: Session, obj_cls):
    """
    Yield all objects of a given class
    """
    yield from session.query(obj_cls)


def enumerate_where(session: Session, obj_cls, **kwargs):
    """
    Yield all objects of a given class verifying conditions defined by kwargs
    """
    yield from session.query(obj_cls).filter_by(**kwargs)
