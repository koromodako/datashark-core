"""Platform-related helpers
"""
from pathlib import Path
from datetime import datetime
from tempfile import gettempdir

CW_DIR = Path.cwd()
CASE_DIR = CW_DIR / datetime.now().strftime('ds_%Y-%m-%dT%H-%M-%S_db')
HOME_DIR = Path.home()
CACHE_DIR = HOME_DIR / '.cache' / 'datashark'
CONFIG_DIR = HOME_DIR / '.config' / 'datashark'
CONFIG_PATH = CONFIG_DIR / 'datashark.yml'


def _create_dir(base_dir, dirname):
    """Create and return path to base_dir / dirname"""
    directory = base_dir / dirname
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def get_cwd_dir(dirname):
    """Prepend current working directory absolute path to given dirname"""
    return _create_dir(CW_DIR, dirname)


def get_case_dir(dirname):
    """Prepend case directory absolute path to given dirname"""
    return _create_dir(CASE_DIR, dirname)


def get_home_dir(dirname):
    """Prepend home directory absolute path to given dirname"""
    return _create_dir(HOME_DIR, dirname)


def get_cache_dir(dirname):
    """Prepend cache directory absolute path to given dirname"""
    return _create_dir(CACHE_DIR, dirname)


def get_config_dir(dirname):
    """Prepend config directory absolute path to given dirname"""
    return _create_dir(CONFIG_DIR, dirname)


def get_temp_dir():
    """Path to directory used to store temporary files and directories"""
    return Path(gettempdir())
