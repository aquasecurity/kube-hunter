from argparse import ArgumentParser
from kube_hunter.plugins import hookimpl


@hookimpl
def parser_add_arguments(parser):
    """
    This is the default hook implementation for parse_add_argument
    Contains initialization for all default arguments
    """
    parser.add_argument(
        "--list",
        action="store_true",
        help="Displays all tests in kubehunter (add --active flag to see active tests)",
    )

    parser.add_argument("--interface", action="store_true", help="Set hunting on all network interfaces")

    parser.add_argument("--pod", action="store_true", help="Set hunter as an insider pod")

    parser.add_argument("--quick", action="store_true", help="Prefer quick scan (subnet 24)")

    parser.add_argument(
        "--include-patched-versions",
        action="store_true",
        help="Don't skip patched versions when scanning",
    )

    parser.add_argument(
        "--cidr",
        type=str,
        help="Set an IP range to scan/ignore, example: '192.168.0.0/24,!192.168.0.8/32,!192.168.0.16/32'",
    )

    parser.add_argument(
        "--mapping",
        action="store_true",
        help="Outputs only a mapping of the cluster's nodes",
    )

    parser.add_argument(
        "--remote",
        nargs="+",
        metavar="HOST",
        default=list(),
        help="One or more remote ip/dns to hunt",
    )

    parser.add_argument(
        "-c",
        "--custom",
        nargs="+",
        metavar="HUNTERS",
        default=list(),
        help="Custom hunting. Only given hunter names will register in the hunt."
        "for a list of options run `--list --raw-hunter-names`",
    )

    parser.add_argument(
        "--raw-hunter-names",
        action="store_true",
        help="Use in combination with `--list` to display hunter class names to pass for custom hunting flag",
    )

    parser.add_argument(
        "--k8s-auto-discover-nodes",
        action="store_true",
        help="Enables automatic detection of all nodes in a Kubernetes cluster "
        "by quering the Kubernetes API server. "
        "It supports both in-cluster config (when running as a pod), "
        "and a specific kubectl config file (use --kubeconfig to set this). "
        "By default, when this flag is set, it will use in-cluster config. "
        "NOTE: this is automatically switched on in --pod mode.",
    )

    parser.add_argument(
        "--service-account-token",
        type=str,
        metavar="JWT_TOKEN",
        help="Manually specify the service account jwt token to use for authenticating in the hunting process "
        "NOTE: This overrides the loading of the pod's bounded authentication when running in --pod mode",
    )

    parser.add_argument(
        "--kubeconfig",
        type=str,
        metavar="KUBECONFIG",
        default=None,
        help="Specify the kubeconfig file to use for Kubernetes nodes auto discovery "
        " (to be used in conjuction with the --k8s-auto-discover-nodes flag.",
    )

    parser.add_argument("--active", action="store_true", help="Enables active hunting")

    parser.add_argument(
        "--enable-cve-hunting",
        action="store_true",
        help="Show cluster CVEs based on discovered version (Depending on different vendors, may result in False Positives)",
    )

    parser.add_argument(
        "--log",
        type=str,
        metavar="LOGLEVEL",
        default="INFO",
        help="Set log level, options are: debug, info, warn, none",
    )

    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Path to a log file to output all logs to",
    )

    parser.add_argument(
        "--report",
        type=str,
        default="plain",
        help="Set report type, options are: plain, yaml, json",
    )

    parser.add_argument(
        "--dispatch",
        type=str,
        default="stdout",
        help="Where to send the report to, options are: "
        "stdout, http (set KUBEHUNTER_HTTP_DISPATCH_URL and "
        "KUBEHUNTER_HTTP_DISPATCH_METHOD environment variables to configure)",
    )

    parser.add_argument("--statistics", action="store_true", help="Show hunting statistics")

    parser.add_argument("--network-timeout", type=float, default=5.0, help="network operations timeout")

    parser.add_argument(
        "--num-worker-threads",
        type=int,
        default=800,
        help="In some environments the default thread count (800) can cause the process to crash. "
        "In the case of a crash try lowering the thread count",
    )


def parse_args(add_args_hook):
    """
    Function handles all argument parsing

    @param add_arguments: hook for adding arguments to it's given ArgumentParser parameter
    @return: parsed arguments dict
    """
    parser = ArgumentParser(description="kube-hunter - hunt for security weaknesses in Kubernetes clusters")
    # adding all arguments to the parser
    add_args_hook(parser=parser)

    args = parser.parse_args()
    if args.cidr:
        args.cidr = args.cidr.replace(" ", "").split(",")
    return args
