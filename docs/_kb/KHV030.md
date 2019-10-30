---
vid: KHV030
title: Possible DNS Spoof
categories: [Identity Theft]
---

# {{ page.vid }} - {{ page.title }}

## Issue description

Your Kubernetes DNS setup is vulnerable to spoofing attacks which impersonate your DNS for malicious purposes.  
In this case the exploited vulnerability was ARP spoofing, but other methods could be used as well.

## Remediation

Consider using DNS over TLS. CoreDNS (the common DNS server for Kubernetes) supports this out of the box, but your client applications might not.

## References

- [DNS Spoofing on Kubernetes Clusters](https://blog.aquasec.com/dns-spoofing-kubernetes-clusters)
- [KHV020 - Possible Arp Spoof]({{ site.baseurl }}{% link _kb/KHV020.md %})
- [CoreDNS DNS over TLS](https://coredns.io/manual/toc/#specifying-a-protocol)
- [DNS over TLS spec](https://tools.ietf.org/html/rfc7858)