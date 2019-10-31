---
vid: KHV020
title: Possible Arp Spoof
categories: [IdentityTheft]
---

# {{ page.vid }} - {{ page.title }}

## Issue description

When using a basic (but common) container networking in the cluster, containers on the same host are bridged togeather to form a virtual layer 2 network. This setup, which is also common for Kubernetes installations. What's also common in Kubernetes installations, is that the `NET_RAW` capability is granted to Pods, allowing them low level access to network interactions. By pairing these two issues together, a malicious Pod running on the cluster could abusing the ARP protocol (used to discover MAC address by IP) in order to spoof the IP address of another pod on same node, thus making other pods on the node talk to the attacker's Pod instead of the legitimate Pod.

## Remediation

Consider dropping the `NET_RAW` capability from your pods using `Pod.spec.securityContext.capabilities`

## References

- [DNS Spoofing on Kubernetes Clusters](https://blog.aquasec.com/dns-spoofing-kubernetes-clusters)
- [Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
