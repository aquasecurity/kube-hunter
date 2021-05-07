from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class Config:
    """Config is a configuration container.
    It contains the following fields:
    - active: Enable active hunters
    - cidr: Network subnets to scan
    - dispatcher: Dispatcher object
    - include_patched_version: Include patches in version comparison
    - interface: Interface scanning mode
    - list_hunters: Print a list of existing hunters
    - log_level: Log level
    - log_file: Log File path
    - mapping: Report only found components
    - network_timeout: Timeout for network operations
    - pod: From pod scanning mode
    - quick: Quick scanning mode
    - remote: Hosts to scan
    - report: Output format
    - statistics: Include hunters statistics
    """

    active: bool = False
    cidr: Optional[str] = None
    dispatcher: Optional[Any] = None
    include_patched_versions: bool = False
    interface: bool = False
    log_file: Optional[str] = None
    mapping: bool = False
    network_timeout: float = 5.0
    pod: bool = False
    quick: bool = False
    remote: Optional[str] = None
    reporter: Optional[Any] = None
    statistics: bool = False
    k8s_auto_discover_nodes: bool = False
    kubeconfig: Optional[str] = None


_config: Optional[Config] = None


def get_config() -> Config:
    if not _config:
        raise ValueError("Configuration is not initialized")
    return _config


def set_config(new_config: Config) -> None:
    global _config
    _config = new_config
