"""Filesystem-related helpers
"""
from pathlib import Path
from tempfile import gettempdir
from . import LOGGER
from .config import DatasharkConfiguration


def ensure_parent_dir(filepath: Path):
    """Ensure parent directory hierarchy exists for given filepath"""
    filepath.parent.mkdir(parents=True, exist_ok=True)


def get_tempdir() -> Path:
    """Retrieve temporary directory"""
    return Path(gettempdir())


def get_workdir(config: DatasharkConfiguration) -> Path:
    """Retrieve wordir from datashark configuration"""
    workdir = config.get('datashark.agent.workdir', type=Path)
    if not workdir.is_absolute():
        raise ValueError("workdir shall be an absolute path!")
    workdir = workdir.resolve()
    if not workdir.is_dir():
        raise ValueError("workdir shall be an existing directory!")
    return workdir


def prepend_workdir(config: DatasharkConfiguration, relative_path: Path) -> Path:
    """Prepend workdir and prevent path traversal"""
    workdir = get_workdir(config)
    filepath = (workdir / relative_path).resolve()
    if not filepath.is_relative_to(workdir):
        LOGGER.warning("workdir: %s", workdir)
        LOGGER.warning("filepath: %s", filepath)
        raise ValueError("path traversal attempt prevented!")
    return filepath
