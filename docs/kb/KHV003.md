---
vid: KHV003
title: Azure Metadata Exposure
categories: [Information Disclosure]
---

# {{ page.vid }} - {{ page.title }}

## Issue description

Microsoft Azure provides an internal HTTP endpoint that exposes information from the cloud platform to workloads running in a VM. The endpoint is accessible to every workload running in the VM. An attacker that is able to execute a pod in the cluster may be able to query the metadata service and discover additional information about the environment.

## Remediation

Consider using AAD Pod Identity. A Microsoft project that allows scoping the identity of workloads to Kubernetes Pods instead of VMs (instances).

## References

- [Azure Instance Metadata service](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service)
- [AAD Pod Identity](https://github.com/Azure/aad-pod-identity#demo)
