"""Datetime-related helpers
"""
from datetime import datetime


def now(fmt):
    """Current datetime as a string using given format"""
    return datetime.now().strftime(fmt)


def now_iso(timespec='seconds'):
    """Current datetime as a string using ISO format with given timespec"""
    return datetime.now().isoformat(timespec)
