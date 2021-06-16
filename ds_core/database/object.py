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
    declarative_base,
    sessionmaker,
    relationship,
)
from sqlalchemy.engine import create_engine
from .. import LOGGER
from ..redis import REDIS
from ..config import CONFIG
from ..platform import get_case_dir

ENGINE_URL = CONFIG.get_(
    'datashark',
    'database',
    'url',
    default=None,
)

if not ENGINE_URL:
    DEFAULT_DB = get_case_dir('db') / 'datashark.db'
    DEFAULT_DB.touch()
    ENGINE_URL = f'sqlite:///{DEFAULT_DB}'

LOGGER.info("creating engine using %s", ENGINE_URL)
ENGINE = create_engine(ENGINE_URL)

Base = declarative_base()
Session = sessionmaker(bind=ENGINE)

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


with REDIS.lock('database-init.lock', blocking_timeout=None):
    Base.metadata.create_all(ENGINE)
