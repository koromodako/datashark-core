"""Dispatcher-related helpers
"""
from rq import Queue
from redis import Redis
from .api import Object
from .yara import matching_plugins
from .plugin import PluginMeta

REDIS_CONN = Redis()
DS_PLUGIN_JOBS = Queue('ds_plugin_jobs', connection=REDIS_CONN)
DS_DISPATCH_JOBS = Queue('ds_dispatch_jobs', connection=REDIS_CONN)


def _dispatch(obj: Object):
    """Enqueue a plugin job"""
    for name in matching_plugins(obj):
        plugin = PluginMeta.REGISTERED[name]
        DS_PLUGIN_JOBS.enqueue(plugin.process, obj)


def enqueue_dispatch(obj):
    """Enqueue a dispatch job"""
    DS_DISPATCH_JOBS.enqueue(_dispatch, obj)
