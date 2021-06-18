'''Plugin-related helpers

class PluginTemplate(Plugin, metaclass=PluginMeta):
    NAME = 'template'
    DESCRIPTION = """
    This is a long description to describe what the
    plugin does.
    """
    YARA_RULE_BODY = """
    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"
    condition:
        $a or $b or $c
    """

    def process(self, obj):
        """
        This method will be called only if plugin's YARA_RULE_BODY matched for
        given object meaning that it is worth trying to process.
        """
        raise NotImplementedError("template plugin is not meant to be called!")

'''
from abc import ABCMeta, abstractmethod
from pprint import pformat
from typing import Callable, Set, List, Dict, Union, Optional
from importlib.metadata import entry_points
from textwrap import dedent
from yarl import URL
from . import LOGGER, BANNER
from .api import Artifact, Result
from .config import DSConfiguration, DEFAULT_CONFIG_PATH
from .dispatch import dispatch
from .database import (
    Format,
    Session,
    Encryption,
    Compression,
    backend_register_artifact,
    backend_register_artifact_tags,
    backend_register_artifact_properties,
)
from .database.object import init_database_session


class Plugin(metaclass=ABCMeta):
    """Plugin abstract class"""

    YARA_MATCH_ALL = """
    condition:
        true
    """

    def __init__(self, config: DSConfiguration):
        self._config = config
        self._session = None

    def __enter__(self):
        self._session = init_database_session(self.config)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._session.close()

    @property
    def name(self):
        """Plugin's name"""
        return getattr(self, 'NAME')

    @property
    def config(self):
        """Plugin's configuration"""
        return self._config

    @property
    def session(self):
        """Plugin's database session"""
        return self._session

    @property
    def depends_on(self):
        """
        Plugin's dependencies (meaning other plugins which shall run first)
        """
        return getattr(self, 'DEPENDS_ON')

    @property
    def description(self):
        """Plugin's description"""
        return dedent(getattr(self, 'DESCRIPTION'))

    @property
    def yara_rule_body(self):
        """Plugin's full yara rule"""
        return dedent(getattr(self, 'YARA_RULE_BODY'))

    @abstractmethod
    def process(self, artifact: Artifact) -> Result:
        """
        This method will be called only if plugin's YARA_RULE_BODY matched for
        given object meaning that it is worth trying to process.
        """

    def register_artifact(
        self,
        fmt: Format,
        artifact_path: str,
        artifact_query: Optional[dict] = None,
        encr: Optional[Encryption] = None,
        comp: Optional[Compression] = None,
        parent: Optional[Artifact] = None,
    ) -> Artifact:
        """Use this to register an artifact in the artifact database"""
        scheme_parts = [fmt.value]
        if encr:
            scheme_parts.append(encr.value)
        if comp:
            scheme_parts.append(comp.value)
        host = str(parent.uuid) if parent else Artifact.LOCALHOST
        url = URL.build(
            scheme='+'.join(scheme_parts),
            host=host,
            path=artifact_path,
            query=artifact_query,
        )
        artifact = Artifact(url, parent)
        backend_register_artifact(self.session, artifact)
        LOGGER.info("registered new artifact: %s", artifact)
        dispatch(self.config, artifact)
        return artifact

    def register_artifact_tags(
        self,
        artifact: Artifact,
        tags: Union[List[str], Set[str]],
    ):
        """Add tags related to an artifact"""
        backend_register_artifact_tags(self.session, artifact, set(tags))
        LOGGER.info("registered artifact tags: %s -> %s", artifact, tags)

    def register_artifact_properties(
        self,
        artifact: Artifact,
        properties: Dict[str, Union[bytes, bytearray, str, int, float]],
    ):
        """Add properties related to an artifact"""
        backend_register_artifact_properties(
            self.session, artifact, properties
        )
        LOGGER.info(
            "registered artifact properties: %s -> %s",
            artifact,
            pformat(properties),
        )


def load_installed_plugins() -> bool:
    """Dynamically load installed plugins"""
    eps = entry_points()
    loaded = False
    for entry_point in eps.get('datashark_plugin', []):
        loaded = True
        entry_point.load()
    return loaded


def _test_app_parse_args():
    """Parse command line arguments for generic plugin test app"""
    from pathlib import Path
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument(
        '--config',
        '-c',
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Configuration file",
    )
    parser.add_argument(
        'filepath',
        type=Path,
        help="Path of the file to be used to test plugin",
    )
    args = parser.parse_args()
    args.config = DSConfiguration(args.config)
    return args


def generic_plugin_test_app(
    instanciate_func: Callable[[DSConfiguration], Plugin], fmt: Format
):
    """Common test function for plugins"""
    LOGGER.info(BANNER)
    args = _test_app_parse_args()
    with instanciate_func(args.config) as plugin:
        artifact = plugin.register_artifact(fmt, str(args.filepath.absolute()))
        plugin.process(artifact)
