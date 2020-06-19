from argparse import ArgumentParser
from tests.plugins import test_hooks
from kube_hunter.plugins import initialize_plugin_manager


def test_all_plugin_hooks():
    pm = initialize_plugin_manager()
    pm.register(test_hooks)

    # Testing parser_add_arguments
    parser = ArgumentParser("Test Argument Parser")
    results = pm.hook.parser_add_arguments(parser=parser)
    assert test_hooks.return_string in results

    # Testing load_plugin
    results = pm.hook.load_plugin(args=[])
    assert test_hooks.return_string in results
