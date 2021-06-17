import logging
import kubernetes


def list_all_k8s_cluster_nodes(kube_config=None, client=None):
    logger = logging.getLogger(__name__)
    try:
        if kube_config:
            logger.info("Attempting to use kubeconfig file: %s", kube_config)
            kubernetes.config.load_kube_config(config_file=kube_config)
        else:
            logger.info("Attempting to use in cluster Kubernetes config")
            kubernetes.config.load_incluster_config()
    except kubernetes.config.config_exception.ConfigException:
        logger.exception("Failed to initiate Kubernetes client")
        return

    try:
        if client is None:
            client = kubernetes.client.CoreV1Api()
        ret = client.list_node(watch=False)
        logger.info("Listed %d nodes in the cluster" % len(ret.items))
        for item in ret.items:
            for addr in item.status.addresses:
                yield addr.address
    except:
        logger.exception("Failed to list nodes from Kubernetes")
