import logging
from kubernetes import client, config


def list_all_k8s_cluster_nodes(kube_config=None):
    logger = logging.getLogger(__name__)
    try:
        if kube_config:
            logger.info("Attempting to use kubeconfig file: %s", kube_config)
            config.load_kube_config(config_file=kube_config)
        else:
            logger.info("Attempting to use in cluster Kubernetes config")
            config.load_incluster_config()
    except config.config_exception.ConfigException:
        logger.exception("Failed to initiate Kubernetes client")
        return

    try:
        ret = client.CoreV1Api().list_node(watch=False)
        logger.info("Listed %d nodes in the cluster" % len(ret.items))
        for item in ret.items:
            addresses = item.status.addresses
            for addr in addresses:
                yield addr.address
    except:
        logger.exception("Failed to list nodes from Kubernetes")
