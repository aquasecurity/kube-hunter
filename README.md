# Kube Hunter

Insecure Kubernetes clusters detection tool.

## Installation

Run the following commands to clone and install pre-requisites:

```bash
git clone git@bitbucket.org:scalock/kube-hunter.git
cd kube-hunter
pip install -R requirements.txt
./kube-hunter -h
```

## Current Features

The following action are currently supported:

### Hunt

Supplied a host IP, the tool will search for open Kubernetes services,
listening to default ports.  
For each service found, it will check if it is insecure and grants
capabilities.  

```bash
./kube-hunter hunt 127.0.0.1
```

### Scan

Supplied a subnet address (CIDR notation), the tool will scan for
hosts with open Kubernetes services.

## Supported Kubernetes Services

The tool currently supports the following services:
* Kubernetes Dashboard
