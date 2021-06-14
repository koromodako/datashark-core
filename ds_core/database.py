"""Database-related helpers
"""
from enum import Enum
from typing import Optional
from yarl import URL
from . import LOGGER
from .api import Artifact


class Format(Enum):
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
    # raw disk
    RAW = 'raw'
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
    FATX = 'fatx' # one of FAT file systems
    # HFS file systems
    HFS = 'hfs'
    HFS_LEGACY = 'hfslegacy'
    HFSX = 'hfsx' # one of HFS file systems
    # APFS file system
    APFS = 'apfs'
    # NTFS file system
    NTFS = 'ntfs'
    # UFS1 file system
    UFS1 = 'ufs1'
    UFS1B = 'ufs1b'
    UFS2 = 'ufs2'
    UFSX = 'ufsx' # one of HFS file systems
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


class Encryption(Enum):
    # LUKS
    LUKS = 'luks'


class Compression(Enum):
    # XZ compression
    XZ = 'xz'
    # LZ4 compression
    LZ4 = 'lz4'
    # LZMA compression
    LZMA = 'lzma'
    # GZIP compression
    GZIP = 'gzip'
    # BZIP2 compression
    BZIP2 = 'bzip2'


def register_artifact(
    fmt: Format,
    artifact_path: str,
    artifact_query: Optional[dict] = None,
    encr: Optional[Encryption] = None,
    comp: Optional[Compression] = None,
    parent: Optional[Artifact] = None,
) -> Artifact:
    """Use this to register an artifact in the artifact database"""
    scheme_parts = [fmt.value]
    if encr:
        scheme_parts.append(encr.value)
    if comp:
        scheme_parts.append(comp.value)
    host = str(parent.uuid) if parent else Artifact.LOCALHOST
    url = URL.build(
        scheme='+'.join(scheme_parts),
        host=host,
        path=artifact_path,
        query=artifact_query,
    )
    artifact = Artifact(url, parent)
    LOGGER.info("registered new artifact: %s", artifact)
    return artifact
