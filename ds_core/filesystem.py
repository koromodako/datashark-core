"""Filesystem-related helpers
"""


def ensure_parent_dir(filepath):
    filepath.parent.mkdir(parents=True, exist_ok=True)
