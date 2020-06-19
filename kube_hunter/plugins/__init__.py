import pluggy

from kube_hunter.plugins import hookspecs

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
    from kube_hunter.conf import parser

    pm.register(parser)

    return pm
