"""Database object mappings
"""
import enum
from sqlalchemy import (
    Text,
    Enum,
    Column,
    Integer,
    DateTime,
    ForeignKey,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship, declarative_base


Base = declarative_base()


class User(Base):
    """
    A user
    """

    __tablename__ = 'user'
    # attributes
    id = Column(Integer, primary_key=True)
    slug = Column(Text, nullable=False, unique=True, index=True)
    # relationships
    contributions = relationship('Contribution', back_populates='user')


class Case(Base):
    """
    A case
    """

    __tablename__ = 'case'
    # attributes
    id = Column(Integer, primary_key=True)
    slug = Column(Text, nullable=False, unique=True, index=True)
    # relationships
    sources = relationship('Source', back_populates='case')
    contributions = relationship('Contribution', back_populates='case')


class Contribution(Base):
    """
    Datashark contribution linking a user to a case (will add roles in the future)
    """

    __tablename__ = 'contribution'
    __table_args__ = (UniqueConstraint('user_id', 'case_id'),)
    # attributes
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    case_id = Column(Integer, ForeignKey('case.id'))
    # relationships
    user = relationship('User', back_populates='contributions')
    case = relationship('Case', back_populates='contributions')


class OS(enum.Enum):
    """
    OS enumeration
    """

    LINUX = 'linux'
    MACOS = 'macos'
    WINDOWS = 'windows'


class HostUID(Base):
    """
    Host unique identifier
    """

    __tablename__ = 'host_uid'
    # attributes
    id = Column(Integer, primary_key=True)
    os = Column(Enum(OS), nullable=False, index=True)
    slug = Column(Text, nullable=False, unique=True, index=True)
    # relationships
    sources = relationship('Source', back_populates='hostname')


class UserUID(Base):
    """
    User unique identifier
    """

    __tablename__ = 'user_uid'
    # attributes
    id = Column(Integer, primary_key=True)
    slug = Column(Text, nullable=False, unique=True, index=True)
    # relationships
    sources = relationship('Source', back_populates='username')


class Source(Base):
    """
    An artifact source related to a case, a host uid and possibly a user uid
    """

    __tablename__ = 'source'
    __table_args__ = (
        UniqueConstraint('case_id', 'host_uid_id', 'user_uid_id'),
    )
    # attributes
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey('case.id'), nullable=False)
    host_uid_id = Column(Integer, ForeignKey('host_uid.id'), nullable=False)
    user_uid_id = Column(Integer, ForeignKey('user_uid.id'), nullable=True)
    # relationships
    case = relationship('Case', back_populates='sources')
    host_uid = relationship('HostUID', back_populates='sources')
    user_uid = relationship('UserUID', back_populates='sources')
    artifacts = relationship('Artifact', back_populates='source')


class Event(Base):
    """
    An event with properties linked to an artifact
    """

    __tablename__ = 'event'
    # attributes
    id = Column(Integer, primary_key=True)
    datetime = Column(DateTime, nullable=False, index=True)
    artifact_id = Column(
        Integer, ForeignKey('artifact.id'), nullable=False, index=True
    )
    # relationships
    artifact = relationship('Artifact', back_populates='events')
    properties = relationship('Property', back_populates='event')


class Artifact(Base):
    """
    An artifact with properties linked to a source, possibly linked to events
    """

    __tablename__ = 'artifact'
    # attributes
    id = Column(Integer, primary_key=True)
    slug = Column(Text, nullable=False, unique=True, index=True)
    source_id = Column(Integer, ForeignKey('source.id'), unique=True, index=True)
    # relationships
    source = relationship('Source', back_populates='artifacts')
    events = relationship('Event', back_populates='artifact')
    properties = relationship('Property', back_populates='artifact')


class PropertyName(Base):
    """
    Property name
    """

    __tablename__ = 'property_name'
    # attributes
    id = Column(Integer, primary_key=True)
    data = Column(Text, unique=True, index=True)
    # relationships
    properties = relationship('Property', back_populates='name')


class PropertyValue(Base):
    """
    Property value
    """

    __tablename__ = 'property_value'
    # attributes
    id = Column(Integer, primary_key=True)
    data = Column(Text, unique=True, index=True)
    # relationships
    properties = relationship('Property', back_populates='value')


class Property(Base):
    """
    Property linking a parent (event or artifact) to a name and value
    """

    __tablename__ = 'property'
    # attributes
    id = Column(Integer, primary_key=True)
    ## parent (one of)
    event_id = Column(Integer, ForeignKey('event.id'), nullable=True)
    artifact_id = Column(Integer, ForeignKey('artifact.id'), nullable=True)
    ## name & value
    name_id = Column(Integer, ForeignKey('property_name.id'), nullable=False)
    value_id = Column(Integer, ForeignKey('property_value.id'), nullable=False)
    # relationships
    event = relationship('Event', back_populates='properties')
    artifact = relationship('Artifact', back_populates='properties')
    name = relationship('PropertyName', back_populates='properties')
    value = relationship('PropertyValue', back_populates='properties')
