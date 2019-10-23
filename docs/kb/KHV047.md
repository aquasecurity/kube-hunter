---
vid: KHV047
title: Pod With Mount To /var/log
categories: [Privilege Escalation]
---

# {{ page.vid }} - {{ page.title }}

## Issue description

Kubernetes uses `/var/log/pods` on nodes to store Pods log files. When running `kubectl logs` the kubelet is fetching the pod logs from that directory. If a container has write access to `/var/log` it can create arbitrary files, or symlink to other files on the host. Those would be read by the kubelet when a user executes `kubectl logs`.

## Remediation

Consider disallowing running as root: 
Using Kubernetes Pod Security Policies with `MustRunAsNonRoot` policy.  
Aqua users can use a Runtime Policy with `Volume Blacklist`.

Consider disallowing writable host mounts to `/var/log`:
Using Kubernetes Pod Security Policies with `AllowedHostPaths` policy.  
Aqua users can  use a Runtime Policy with `Blacklisted OS Users and Groups`.

## References

- [Kubernetes Pod Escape Using Log Mounts](https://blog.aquasec.com/kubernetes-security-pod-escape-log-mounts)
- [Pod Security Policies - Volumes and file systems](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#volumes-and-file-systems)
- [Pod Security Policies - Users and groups](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#users-and-groups)
