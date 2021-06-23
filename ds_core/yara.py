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


CACHE_FILENAME = 'rules.yar'
COMPILED_CACHE_FILENAME = 'rules.yar.comp'


def update_cached_yara_rules(config: DSConfiguration) -> bool:
    LOGGER.debug("updating cached rules...")
    rules_as_text = ''
    for plugin in PluginMeta.REGISTERED.values():
        LOGGER.debug("adding rule %s", plugin.NAME)
        rules_as_text += ''.join(
            [
                f"rule {plugin.NAME}\n",
                "{",
                indent(dedent(plugin.YARA_RULE_BODY), '    '),
                "}\n",
            ]
        )
    LOGGER.info("compiling yara rules...")

    try:
        rules = yara.compile(source=rules_as_text)
    except yara.SyntaxError as exc:
        LOGGER.critical("failed to compile yara rules: %s", exc)
        LOGGER.critical("attempted to compile:\n%s", rules_as_text)
        return False
    cache_dir = config.get('datashark.core.directory.cache', type=Path)
    ensure_parent_dir(cache_dir)
    cache_filepath = cache_dir / CACHE_FILENAME
    with cache_filepath.open('w') as fstream:
        fstream.write(rules_as_text)
    compiled_cache_filepath = cache_dir / COMPILED_CACHE_FILENAME
    rules.save(str(compiled_cache_filepath))
    return True


def matching_plugins(config: DSConfiguration, artifact: Artifact):
    cache_dir = config.get('datashark.core.directory.cache', type=Path)
    compiled_cache_filepath = cache_dir / COMPILED_CACHE_FILENAME
    LOGGER.info("loading yara rules from cache...")
    rules = yara.load(str(compiled_cache_filepath))
    filepath = artifact.filepath(config.get('datashark.core.directory.temp', type=Path))
    LOGGER.info("attempting to match rules against %s ...", filepath)
    results = rules.match(str(filepath), fast=True)
    matched = {result.rule for result in results}
    LOGGER.info("plugins matched: %s", matched)
    return matched
