"""Filesystem-related helpers
"""
from pathlib import Path


def ensure_parent_dir(filepath: Path):
    """Ensure parent directory hierarchy exists for given filepath"""
    filepath.parent.mkdir(parents=True, exist_ok=True)


def prepend_workdir(workdir: Path, relative_path: Path):
    """Prepend workdir and prevent path traversal"""
    filepath = (workdir / relative_path).resolve()
    if not filepath.is_relative_to(workdir):
        raise ValueError("path traversal attempt prevented!")
    return filepath
