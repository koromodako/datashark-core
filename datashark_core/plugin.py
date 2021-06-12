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
import re
from abc import ABCMeta, abstractmethod
from textwrap import dedent, indent
from .api import Object, Result

NAME_RE = re.compile(r'\w+')

class PluginMeta(type):
    """Datashark plugin metaclass"""
    PLUGINS = {}
    MANDATORY = {
        'NAME',
        'DEPENDS_ON',
        'DESCRIPTION',
        'YARA_RULE_BODY'
    }

    def __new__(cls, name, bases, dct):
        # build new class
        ncls = super().__new__(cls, name, bases, dct)
        # perform mandatory attributes check
        mandatory_attributes = PluginMeta.MANDATORY
        for mandatory in mandatory_attributes:
            if mandatory in dct:
                continue
            raise NotImplementedError(
                f"class '{name}' shall define mandatory '{mandatory}'!"
            )
        # perform name check
        dct_name = dct['NAME']
        if not NAME_RE.fullmatch(dct_name):
            raise ValueError(
                f"class '{name}' NAME attribute must validate regexp '{NAME_RE.pattern}'!"
            )
        if dct_name in PluginMeta.PLUGINS:
            raise ValueError(
                f"class '{name}' NAME already registered by another plugin!"
            )
        PluginMeta.PLUGINS[dct_name] = ncls
        # finally return new class
        return ncls


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
    def process(self, obj: Object) -> Result:
        """
        This method will be called only if plugin's YARA_RULE_BODY matched for
        given object meaning that it is worth trying to process.
        """
