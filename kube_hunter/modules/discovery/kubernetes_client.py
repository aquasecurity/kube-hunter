import logging
import kubernetes


def list_all_k8s_cluster_nodes(kube_config=None, client=None):
    logger = logging.getLogger(__name__)
    try:
        if kube_config:
            logger.debug("Attempting to use kubeconfig file: %s", kube_config)
            kubernetes.config.load_kube_config(config_file=kube_config)
        else:
            logger.debug("Attempting to use in cluster Kubernetes config")
            kubernetes.config.load_incluster_config()
    except kubernetes.config.config_exception.ConfigException as ex:
        logger.debug(f"Failed to initiate Kubernetes client: {ex}")
        return

    try:
        if client is None:
            client = kubernetes.client.CoreV1Api()
        ret = client.list_node(watch=False)
        logger.info("Listed %d nodes in the cluster" % len(ret.items))
        for item in ret.items:
            for addr in item.status.addresses:
                yield addr.address
    except Exception as ex:
        logger.debug(f"Failed to list nodes from Kubernetes: {ex}")
