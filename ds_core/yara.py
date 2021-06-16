"""Yara-related helpers
"""
from pathlib import Path
from textwrap import dedent, indent
import yara
from . import LOGGER
from .api import Artifact
from .meta import PluginMeta
from .config import DSConfiguration
from .filesystem import ensure_parent_dir


CACHE_FILENAME = 'rules.cache'


def update_cached_yara_rules(config: DSConfiguration) -> bool:
    LOGGER.debug("updating cached rules...")
    rules_as_text = ''
    for plugin in PluginMeta.REGISTERED.values():
        LOGGER.debug("adding rule %s", plugin.NAME)
        rules_as_text += ''.join([
            f"rule {plugin.NAME}\n",
            "{",
            indent(dedent(plugin.YARA_RULE_BODY), '    '),
            "}\n",
        ])
    LOGGER.info("compiling yara rules...")
    try:
        rules = yara.compile(source=rules_as_text)
    except yara.SyntaxError as exc:
        LOGGER.critical("failed to compile yara rules: %s", exc)
        LOGGER.critical("attempted to compile:\n%s", rules_as_text)
        return False
    cache_filepath = (
        config.get('datashark.core.directory.cache', type=Path) / CACHE_FILENAME
    )
    ensure_parent_dir(cache_filepath)
    rules.save(str(cache_filepath))
    return True


def matching_plugins(config: DSConfiguration, artifact: Artifact):
    cache_filepath = (
        config.get('datashark.core.directory.cache', type=Path) / CACHE_FILENAME
    )
    rules = yara.load(str(cache_filepath))
    results = rules.match(str(artifact.filepath))
    return {result.rule for result in results if result.matches}
