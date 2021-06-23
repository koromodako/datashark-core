"""Dispatcher-related helpers
"""
from rq import Queue
from . import LOGGER
from .api import Artifact
from .yara import matching_plugins
from .meta import load_plugin_instanciate_func
from .config import DSConfiguration
from .database.helper import CORE_REDIS

DS_PLUGIN_JOBS = Queue('ds_plugin_jobs', connection=CORE_REDIS)
DS_DISPATCH_JOBS = Queue('ds_dispatch_jobs', connection=CORE_REDIS)


def _process(name: str, config: DSConfiguration, artifact: Artifact):
    instanciate_func = load_plugin_instanciate_func(name)
    with instanciate_func(config) as plugin:
        return plugin.process(artifact)


def _dispatch(config: DSConfiguration, artifact: Artifact):
    """Enqueue a plugin job"""
    jobs = []
    for name in matching_plugins(config, artifact):
        job = DS_PLUGIN_JOBS.enqueue(_process, args=(name, config, artifact))
        LOGGER.info("new plugin %s job %s for %s", name, job.id, artifact)
        jobs.append(job)
    return jobs


def dispatch(config: DSConfiguration, artifact: Artifact):
    """Enqueue a dispatch job"""
    job = DS_DISPATCH_JOBS.enqueue(_dispatch, args=(config, artifact))
    LOGGER.info("new dispatch job %s for %s", job.id, artifact)
    return job
