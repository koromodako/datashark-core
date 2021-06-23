"""Database-related helpers
"""
from enum import Enum
from pprint import pformat
from typing import Union, List, Set, Dict
from yarl import URL
from sqlalchemy import select
from .. import LOGGER
from ..api import Artifact
from .object import (
    Session,
    DSArtifact,
    DSArtifactTag,
    DSArtifactProperty,
)


class Format(Enum):
    # raw disk data
    RAW = 'raw'
    # undefined data format
    DATA = 'data'
    # a file
    FILE = 'file'
    # deleted file system element
    DELETED = 'deleted'
    # slack space of a file
    SLACK = 'slack'
    # a directory
    DIR = 'dir'
    # sleuthkit-supported format
    TSK = 'tsk'
    # partition
    PART = 'part'
    # VHD virtual disk
    VHD = 'vhd'
    # VMDK virtual disk
    VMDK = 'vmdk'
    # FAT file systems
    FAT12 = 'fat12'
    FAT16 = 'fat16'
    FAT32 = 'fat32'
    FATX = 'fatx'  # one of FAT file systems
    # HFS file systems
    HFS = 'hfs'
    HFS_LEGACY = 'hfslegacy'
    HFSX = 'hfsx'  # one of HFS file systems
    # APFS file system
    APFS = 'apfs'
    # NTFS file system
    NTFS = 'ntfs'
    # UFS1 file system
    UFS1 = 'ufs1'
    UFS1B = 'ufs1b'
    UFS2 = 'ufs2'
    UFSX = 'ufsx'  # one of HFS file systems
    # EXT file systems
    EXT2 = 'ext2'
    EXT3 = 'ext3'
    EXT4 = 'ext4'
    EXTX = 'extx'
    # swap partition
    SWAP = 'swap'
    # YAFFS2 file system
    EXFAT = 'exfat'
    # YAFFS2 file system
    YAFFS2 = 'yaffs2'
    # ISO9660 file system
    ISO9660 = 'iso9660'
    # SQLite3 database
    SQLITE3 = 'sqlite3'
    # Windows SuperFetch database
    AGDB = 'agdb'
    # Windows 9x/Me Registry File (CREG)
    CREG = 'creg'
    # Extensible Storage Engine (ESE) Database File (EDB)
    ESEDB = 'esedb'
    # Windows Event Log (EVT)
    EVT = 'evt'
    # Windows XML Event Log (EVTX)
    EVTX = 'evtx'
    # PE/COFF Executable (EXE)
    EXE = 'exe'
    # Windows Shortcut File (LNK)
    LNK = 'lnk'
    # Microsoft Internet Explorer (MSIE) Cache File (index.dat)
    MSIECF = 'msiecf'
    # Microsoft Outlook Nickfile (NK2)
    NK2 = 'nk2'
    # Notes Storage Facility (NSF) database
    NSFDB = 'nsfdb'
    # OLE 2 Compound File (OLECF)
    OLECF = 'olecf'
    # Personal Folder File (PFF)
    PFF = 'pff'
    # Windows NT Registry File (REGF)
    REGF = 'regf'
    # Windows Prefetch File (SCCA)
    SCCA = 'scca'
    # AR archive
    AR = 'ar'
    # Zip Archive
    ZIP = 'zip'
    # RAR Archive
    RAR = 'rar'
    # TAR Archive
    TAR = 'tar'
    # 7Zip Archive
    _7ZIP = '7zip'
    # CPIO Archive
    CPIO = 'cpio'


def _get_one(session: Session, obj_cls, **kwargs):
    """Retrieve exactly one object from database or raise"""
    return session.query(obj_cls).filter_by(**kwargs).one()


def _get_or_make(session: Session, obj_cls, **kwargs):
    """Retrieve object from database or make a new one"""
    obj = session.query(obj_cls).filter_by(**kwargs).one_or_none()
    if obj:
        return obj
    return obj_cls(**kwargs)


def backend_register_artifact(session: Session, artifact: Artifact):
    """Register artifact in database"""
    session.add(
        DSArtifact(
            uuid=str(artifact.uuid),
            parent=str(artifact.parent),
            url=artifact.url.human_repr(),
        )
    )


def backend_register_artifact_tags(
    session: Session,
    artifact: Artifact,
    tags: Union[List[str], Set[str]],
):
    """Register artifact tags in database"""
    ds_artifact = _get_one(session, DSArtifact, uuid=str(artifact.uuid))
    ds_artifact.tags = [
        _get_or_make(session, DSArtifactTag, value=tag) for tag in set(tags)
    ]
    session.add(ds_artifact)


def backend_register_artifact_properties(
    session: Session,
    artifact: Artifact,
    properties: Dict[str, Union[bytes, bytearray, str, int, float]],
):
    """Register artifact properties in database"""
    ds_artifact = _get_one(session, DSArtifact, uuid=str(artifact.uuid))
    ds_artifact.properties = [
        DSArtifactProperty(key=key, value=str(value))
        for key, value in properties.items()
    ]
    session.add(ds_artifact)
