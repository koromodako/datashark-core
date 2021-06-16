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
from importlib.metadata import entry_points
from textwrap import dedent, indent
from . import LOGGER, BANNER
from .api import Artifact, Result
from .database import Session, register_artifact, Format


class Plugin(metaclass=ABCMeta):
    """Plugin abstract class"""

    @property
    def name(self):
        """Plugin's name"""
        return getattr(self, 'NAME')

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
    def yara_rule(self):
        """Plugin's full yara rule"""
        name = self.name
        yara_rule_body = dedent(getattr(self, 'YARA_RULE_BODY'))
        return dedent(
            f"""
            rule {name} {{
            {indent(yara_rule_body, '    ')}
            }}
            """
        )

    @abstractmethod
    def process(self, session: Session, artifact: Artifact) -> Result:
        """
        This method will be called only if plugin's YARA_RULE_BODY matched for
        given object meaning that it is worth trying to process.
        """


def load_installed_plugins():
    """Dynamically load installed plugins"""
    eps = entry_points()
    for entry_point in eps.get('datashark_plugin', []):
        LOGGER.debug("loading plugin %s ...", entry_point.name)
        entry_point.load()


def test_plugin(plugin: Plugin, fmt: Format):
    """Common test function for plugins"""
    from pathlib import Path
    from argparse import ArgumentParser

    LOGGER.info(BANNER)
    parser = ArgumentParser()
    parser.add_argument(
        'filepath',
        type=Path,
        help="Path of the file to be used to test plugin",
    )
    args = parser.parse_args()
    with Session() as session:
        artifact = register_artifact(session, fmt, str(args.filepath.absolute()))
        plugin.process(session, artifact)
        session.commit()
