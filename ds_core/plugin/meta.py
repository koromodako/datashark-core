"""Plugin metaclass
"""
import re
from abc import ABCMeta

NAME_RE = re.compile(r'\w+')


class PluginMeta(ABCMeta):
    """Datashark plugin metaclass"""

    MANDATORY = {'NAME', 'DEPENDS_ON', 'DESCRIPTION', 'YARA_RULE_BODY'}
    REGISTERED = {}

    def __new__(cls, name, bases, namespace, /, **kwargs):
        # build new class
        ncls = super().__new__(cls, name, bases, namespace, **kwargs)
        # perform mandatory attributes check
        mandatory_attributes = PluginMeta.MANDATORY
        for mandatory in mandatory_attributes:
            if mandatory in namespace:
                continue
            raise NotImplementedError(
                f"class '{name}' shall define mandatory '{mandatory}'!"
            )
        # perform name check
        ns_name = namespace['NAME']
        if not NAME_RE.fullmatch(ns_name):
            raise ValueError(
                f"class '{name}' NAME attribute must validate regexp '{NAME_RE.pattern}'!"
            )
        if ns_name in PluginMeta.REGISTERED:
            raise ValueError(
                f"class '{name}' NAME already registered by another plugin!"
            )
        PluginMeta.REGISTERED[ns_name] = ncls
        # finally return new class
        return ncls
