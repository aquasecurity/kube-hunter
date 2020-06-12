import pluggy
from argparse import ArgumentParser

hookspec = pluggy.HookspecMarker("kube-hunter")


@hookspec
def parser_add_arguments(parser: ArgumentParser):
    """Add arguments to the ArgumentParser.

    If a plugin requires an aditional argument, it should implement this hook
    and add the argument to the Argument Parser

    @param parser: an ArgumentParser, calls parser.add_argument on it
    """


@hookspec
def load_plugin(args):
    """Plugins that wish to execute code after the argument parsing
    should implement this hook.

    @param args: all parsed arguments passed to kube-hunter
    """
