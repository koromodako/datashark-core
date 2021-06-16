"""Yara-related helpers
"""
from pathlib import Path
from textwrap import dedent, indent
import yara
from . import LOGGER
from .api import Artifact
from .meta import PluginMeta
from .config import DSConfiguration


def rules_cache_from_config(config: DSConfiguration) -> Path:
    return str(
        config.get('datashark.directory.cache', type=Path) / 'rules.cache'
    )


def update_cached_rules(config: DSConfiguration):
    LOGGER.debug("updating cached rules...")
    rules_as_text = ''
    for plugin in PluginMeta.PLUGINS.values():
        LOGGER.debug("adding rule %s", plugin.NAME)
        rules_as_text += dedent(
            f"""
            rule {plugin.NAME} {{
            {indent(dedent(plugin.YARA_RULE_BODY), '    ')}
            }}
            """
        )
    rules = yara.compile(source=rules_as_text)
    rules.save(rules_cache_from_config(config))


def matching_plugins(config: DSConfiguration, artifact: Artifact):
    rules = yara.load(rules_cache_from_config(config))
    results = rules.match(str(artifact.filepath))
    return {result.rule for result in results if result.matches}
