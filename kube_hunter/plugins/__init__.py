import pluggy

from kube_hunter.plugins import hookspecs
from kube_hunter.conf import parser

hookimpl = pluggy.HookimplMarker("kube-hunter")


def initialize_plugin_manager():
    """
    Initializes and loads all default and setup implementations for registered plugins

    @return: initialized plugin manager
    """
    pm = pluggy.PluginManager("kube-hunter")
    pm.add_hookspecs(hookspecs)
    pm.load_setuptools_entrypoints("kube_hunter")

    # default registration of builtin implemented plugins
    pm.register(parser)
    return pm
