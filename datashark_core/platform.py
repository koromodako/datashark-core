"""Platform-related helpers
"""
from pathlib import Path
from tempfile import gettempdir

CACHE_DIR = Path.home().joinpath('.cache', 'datashark')
CONFIG_DIR = Path.home().joinpath('.config', 'datashark')
CONFIG_PATH = CONFIG_DIR.joinpath('datashark.yml')


def get_cache_dir(dirname):
    """Prepend cache absolute path to given dirname"""
    directory = CACHE_DIR.joinpath(dirname)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def get_config_dir(dirname):
    """Prepend config absolute path to given dirname"""
    directory = CONFIG_DIR.joinpath(dirname)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def get_temp_dir():
    """Path to directory used to store temporary files and directories"""
    return Path(gettempdir())
