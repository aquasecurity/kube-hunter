from dataclasses import dataclass, field
from typing import Any, Optional


def get_default_core_hunters():
    return ["FromPodHostDiscovery", "HostDiscovery", "PortDiscovery", "SendFullReport", "Collector", "StartedInfo"]


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
    - num_worker_threads: Add a flag --threads to change the default 800 thread count of the event handler
    - pod: From pod scanning mode
    - quick: Quick scanning mode
    - remote: Hosts to scan
    - report: Output format
    - statistics: Include hunters statistics
    - enable_cve_hunting: enables cve hunting, shows cve results
    """

    active: bool = False
    cidr: Optional[str] = None
    dispatcher: Optional[Any] = None
    include_patched_versions: bool = False
    interface: bool = False
    log_file: Optional[str] = None
    mapping: bool = False
    network_timeout: float = 5.0
    num_worker_threads: int = 800
    pod: bool = False
    quick: bool = False
    remote: Optional[str] = None
    reporter: Optional[Any] = None
    statistics: bool = False
    k8s_auto_discover_nodes: bool = False
    service_account_token: Optional[str] = None
    kubeconfig: Optional[str] = None
    enable_cve_hunting: bool = False
    custom: Optional[list] = None
    raw_hunter_names: bool = False
    core_hunters: list = field(default_factory=get_default_core_hunters)


_config: Optional[Config] = None


def get_config() -> Config:
    if not _config:
        raise ValueError("Configuration is not initialized")
    return _config


def set_config(new_config: Config) -> None:
    global _config
    _config = new_config
