"""Database object mappings
"""
from sqlalchemy import (
    Table,
    Column,
    Integer,
    Text,
    ForeignKey,
)
from sqlalchemy.orm import (
    Session,
    relationship,
    declarative_base,
)
from sqlalchemy.engine import create_engine
from .. import LOGGER
from ..redis import REDIS
from ..config import DSConfiguration


Base = declarative_base()

artifact_tag_rel = Table(
    'artifact_tag_rel',
    Base.metadata,
    Column('artifact_id', ForeignKey('artifact.id'), primary_key=True),
    Column('tag_id', ForeignKey('tag.id'), primary_key=True),
)


class DSArtifactTag(Base):
    __tablename__ = 'tag'

    id = Column(Integer, primary_key=True)
    value = Column(Text, nullable=False, unique=True, index=True)


class DSArtifactProperty(Base):
    __tablename__ = 'property'

    id = Column(Integer, primary_key=True)
    key = Column(Text, nullable=False, index=True)
    value = Column(Text, index=True)

    artifact_id = Column(Integer, ForeignKey('artifact.id'))


class DSArtifact(Base):
    __tablename__ = 'artifact'

    id = Column(Integer, primary_key=True)
    uuid = Column(Text, nullable=False, unique=True, index=True)
    parent = Column(Text, nullable=True, index=True)
    url = Column(Text)

    tags = relationship(
        'DSArtifactTag',
        secondary=artifact_tag_rel,
    )
    properties = relationship('DSArtifactProperty')


def init_database_session(config: DSConfiguration) -> Session:
    LOGGER.info("waiting for init_database_session lock...")
    with REDIS.lock('init_database_session.lock', blocking_timeout=None):
        engine_url = config.get('datashark.core.database.url')
        LOGGER.info("lock acquired, creating engine for: %s", engine_url)
        engine = create_engine(engine_url)
        LOGGER.info("creating database schema if necessary...")
        Base.metadata.create_all(engine)
        LOGGER.info("creating a new session...")
        return Session(engine)
