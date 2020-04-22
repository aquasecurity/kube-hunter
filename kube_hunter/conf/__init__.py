from dataclasses import dataclass, field
from typing import Sequence
from kube_hunter.conf.parser import parse_args
from kube_hunter.conf.logging import setup_logger


@dataclass
class Config:
    """ Config is a configuration container.
    It contains the following fields:
    - interface: Interface scanning mode
    - pod: From pod scanning mode
    - quick: Quick scanning mode
    - include_patched_version: Version comparison include patches
    - cidr: Network subnets to scan
    - mapping: Report only found components
    - remote: Hosts to scan
    - active: Enable active hunters
    - log: Log level
    - report: Output format
    - dispatch: Output target
    - statistics: Include hunters statistics
    - network_timeout: Timeout for network operations
    """

    interface: bool = False
    pod: bool = False
    quick: bool = False
    include_patched_versions: bool = False
    cidr: Sequence[str] = field(default_factory=list)
    mapping: bool = False
    remote: Sequence[str] = field(default_factory=list)
    active: bool = False
    log_level: str = "INFO"
    report: str = "plain"
    dispatch: str = "stdout"
    statistics: bool = False
    network_timeout: float = 5.0


_parsed = parse_args()
config: Config = Config(
    interface=_parsed.interface,
    pod=_parsed.pod,
    quick=_parsed.quick,
    include_patched_versions=_parsed.include_patched_versions,
    cidr=_parsed.cidr,
    mapping=_parsed.mapping,
    remote=_parsed.remote,
    active=_parsed.active,
    log_level=_parsed.log,
    report=_parsed.report,
    dispatch=_parsed.dispatch,
    statistics=_parsed.statistics,
    network_timeout=_parsed.network_timeout,
)
setup_logger(config.log_level)

__all__ = [Config, parse_args, setup_logger, config]
