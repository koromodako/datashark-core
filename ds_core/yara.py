"""Yara-related helpers
"""
import yara
from . import LOGGER
from .api import Artifact
from .meta import PluginMeta
from .platform import get_cache_dir

CACHE_FILE = get_cache_dir('yara') / 'rules'


def update_cached_rules():
    LOGGER.debug("updating cached rules...")
    rules_as_text = ''
    for name, plugin in PluginMeta.PLUGINS.items():
        LOGGER.debug("adding rule %s", name)
        rules_as_text += plugin.yara_rule
    rules = yara.compile(source=rules_as_text)
    rules.save(str(CACHE_FILE))


def matching_plugins(artifact: Artifact):
    rules = yara.load(str(CACHE_FILE))
    results = rules.match(str(artifact.filepath))
    return {result.rule for result in results if result.matches}
