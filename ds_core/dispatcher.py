"""Dispatcher-related helpers
"""
from rq import Queue
from . import LOGGER
from .api import Artifact
from .yara import matching_plugins
from .meta import PluginMeta
from .config import DSConfiguration
from .redis import REDIS

DS_PLUGIN_JOBS = Queue('ds_plugin_jobs', connection=REDIS)
DS_DISPATCH_JOBS = Queue('ds_dispatch_jobs', connection=REDIS)


def _process(name: str, artifact: Artifact):
    plugin = PluginMeta.REGISTERED[name]
    return plugin.process(artifact)


def _dispatch(config: DSConfiguration, artifact: Artifact):
    """Enqueue a plugin job"""
    jobs = []
    for name in matching_plugins(config, artifact):
        job = DS_PLUGIN_JOBS.enqueue(_process, args=(name, artifact))
        LOGGER.info("new plugin %s job %s for %s", name, job.id, artifact)
        jobs.append(job)
    return jobs


def enqueue_dispatch(config: DSConfiguration, artifact: Artifact):
    """Enqueue a dispatch job"""
    job = DS_DISPATCH_JOBS.enqueue(_dispatch, args=(config, artifact))
    LOGGER.info("new dispatch job %s for %s", job.id, artifact)
    return job
