"""Dispatcher-related helpers
"""
from pathlib import Path
from rq import Queue
from . import LOGGER
from .api import Artifact
from .yara import matching_plugins
from .meta import load_plugin_instanciate_func
from .config import DSConfiguration
from .database.helper import CORE_REDIS

DS_PLUGIN_JOBS = Queue('ds_plugin_jobs', connection=CORE_REDIS)
DS_CLEANUP_JOBS = Queue('ds_cleanup_jobs', connection=CORE_REDIS)
DS_DISPATCH_JOBS = Queue('ds_dispatch_jobs', connection=CORE_REDIS)


def _plugin_routine(name: str, config: DSConfiguration, artifact: Artifact):
    """Run given plugin on given artifact"""
    instanciate_func = load_plugin_instanciate_func(name)
    with instanciate_func(config) as plugin:
        return plugin.process(artifact)


def _cleanup_routine(filepath: Path):
    """Unlink file located by filepath"""
    filepath.unlink()


def _dispatch_routine(config: DSConfiguration, artifact: Artifact):
    """Enqueue a plugin job"""
    filepath = artifact.filepath(
        config.get('datashark.core.directory.temp', type=Path)
    )
    # if file size > 0 run plugins else enqueue cleanup job,
    # it might be a mistake made by the extractor.
    plugin_jobs = []
    if filepath.stat().st_size > 0:
        # enqueue jobs for matching plugins
        for name in matching_plugins(config, artifact):
            job = DS_PLUGIN_JOBS.enqueue(
                _plugin_routine,
                args=(name, config, artifact),
                ttl=None,
                job_timeout='1h',
                result_ttl='1m',
                failure_ttl='7d',
            )
            LOGGER.info(
                "new plugin job[%s](name=%s, artifact=%s)",
                name,
                job.id,
                artifact,
            )
            plugin_jobs.append(job)
    # enqueue cleanup job depending on plugin jobs
    cleanup_job = None
    if not artifact.is_localhost:
        cleanup_job = DS_CLEANUP_JOBS.enqueue(
            _cleanup_routine,
            args=(filepath,),
            ttl=None,
            job_timeout='2m',
            result_ttl='1m',
            failure_ttl='7d',
            depends_on=plugin_jobs,
        )
        LOGGER.info(
            "new cleanup job[%s](filepath=%s)", cleanup_job.id, filepath
        )
    return plugin_jobs, cleanup_job


def dispatch(config: DSConfiguration, artifact: Artifact):
    """Enqueue a dispatch job"""
    job = DS_DISPATCH_JOBS.enqueue(
        _dispatch_routine,
        args=(config, artifact),
        ttl=None,
        job_timeout='30m',
        result_ttl='1m',
        failure_ttl='7d',
    )
    LOGGER.info("new dispatch job[%s](artifact=%s)", job.id, artifact)
    return job
