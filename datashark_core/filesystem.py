"""Filesystem-related helpers
"""
from pathlib import Path


def ensure_parent_dir(filepath: Path):
    """Ensure parent directory hierarchy exists for given filepath"""
    filepath.parent.mkdir(parents=True, exist_ok=True)
