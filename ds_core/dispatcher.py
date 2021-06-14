"""Dispatcher-related helpers
"""
from rq import Queue
from redis import Redis
from .api import Artifact
from .yara import matching_plugins
from .plugin import PluginMeta

REDIS_CONN = Redis()
DS_PLUGIN_JOBS = Queue('ds_plugin_jobs', connection=REDIS_CONN)
DS_DISPATCH_JOBS = Queue('ds_dispatch_jobs', connection=REDIS_CONN)


def _process(name: str, artifact: Artifact):
    plugin = PluginMeta.REGISTERED[name]
    return plugin.process(artifact)


def _dispatch(artifact: Artifact):
    """Enqueue a plugin job"""
    jobs = []
    for name in matching_plugins(artifact):
        jobs.append(
            DS_PLUGIN_JOBS.enqueue(
                _process,
                args=(
                    name,
                    artifact,
                ),
            )
        )
    return jobs


def enqueue_dispatch(artifact: Artifact):
    """Enqueue a dispatch job"""
    return DS_DISPATCH_JOBS.enqueue(_dispatch, artifact)
