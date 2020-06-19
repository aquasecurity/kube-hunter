from kube_hunter.plugins import hookimpl

return_string = "return_string"


@hookimpl
def parser_add_arguments(parser):
    return return_string


@hookimpl
def load_plugin(args):
    return return_string
