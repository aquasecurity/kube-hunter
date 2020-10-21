![kube-hunter](https://github.com/aquasecurity/kube-hunter/blob/master/kube-hunter.png)

[![Build Status](https://travis-ci.org/aquasecurity/kube-hunter.svg?branch=master)](https://travis-ci.org/aquasecurity/kube-hunter)
[![codecov](https://codecov.io/gh/aquasecurity/kube-hunter/branch/master/graph/badge.svg)](https://codecov.io/gh/aquasecurity/kube-hunter)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License](https://img.shields.io/github/license/aquasecurity/kube-hunter)](https://github.com/aquasecurity/kube-hunter/blob/master/LICENSE)
[![Docker image](https://images.microbadger.com/badges/image/aquasec/kube-hunter.svg)](https://microbadger.com/images/aquasec/kube-hunter "Get your own image badge on microbadger.com")



kube-hunter hunts for security weaknesses in Kubernetes clusters. The tool was developed to increase awareness and visibility for security issues in Kubernetes environments. **You should NOT run kube-hunter on a Kubernetes cluster that you don't own!**

**Run kube-hunter**: kube-hunter is available as a container (aquasec/kube-hunter), and we also offer a web site at [kube-hunter.aquasec.com](https://kube-hunter.aquasec.com) where you can register online to receive a token allowing you to see and share the results online. You can also run the Python code yourself as described below.

**Explore vulnerabilities**: The kube-hunter knowledge base includes articles about discoverable vulnerabilities and issues. When kube-hunter reports an issue, it will show its VID (Vulnerability ID) so you can look it up in the KB at https://aquasecurity.github.io/kube-hunter/

**Contribute**: We welcome contributions, especially new hunter modules that perform additional tests. If you would like to develop your modules please read [Guidelines For Developing Your First kube-hunter Module](https://github.com/aquasecurity/kube-hunter/blob/master/CONTRIBUTING.md).

[![kube-hunter demo video](https://github.com/aquasecurity/kube-hunter/blob/master/kube-hunter-screenshot.png)](https://youtu.be/s2-6rTkH8a8?t=57s)

Table of Contents
=================

* [Hunting](#hunting)
   * [Where should I run kube-hunter?](#where-should-i-run-kube-hunter)
   * [Scanning options](#scanning-options)
   * [Active Hunting](#active-hunting)
   * [List of tests](#list-of-tests)
   * [Nodes Mapping](#nodes-mapping)
   * [Output](#output)
   * [Dispatching](#dispatching)
* [Deployment](#deployment)
   * [On Machine](#on-machine)
      * [Prerequisites](#prerequisites)
   * [Container](#container)
   * [Pod](#pod)
* [Contribution](#contribution)
         
## Hunting

### Where should I run kube-hunter?

There are three different ways to run kube-hunter, each providing a different approach to detecting weaknesses in your cluster:

Run kube-hunter on any machine (including your laptop), select Remote scanning and give the IP address or domain name of your Kubernetes cluster. This will give you an attackers-eye-view of your Kubernetes setup.

You can run kube-hunter directly on a machine in the cluster, and select the option to probe all the local network interfaces.

You can also run kube-hunter in a pod within the cluster. This indicates how exposed your cluster would be if one of your application pods is compromised (through a software vulnerability, for example).

### Scanning options

First check for these **[pre-requisites](#prerequisites)**.

By default, kube-hunter will open an interactive session, in which you will be able to select one of the following scan options. You can also specify the scan option manually from the command line. These are your options:

1. **Remote scanning**

To specify remote machines for hunting, select option 1 or use the `--remote` option. Example:
`kube-hunter --remote some.node.com`

2. **Interface scanning**

To specify interface scanning, you can use the `--interface` option (this will scan all of the machine's network interfaces). Example:
`kube-hunter --interface`

3. **Network scanning**

To specify a specific CIDR to scan, use the `--cidr` option. Example:
`kube-hunter --cidr 192.168.0.0/24`

### Active Hunting

Active hunting is an option in which kube-hunter will exploit vulnerabilities it finds, to explore for further vulnerabilities.
The main difference between normal and active hunting is that a normal hunt will never change the state of the cluster, while active hunting can potentially do state-changing operations on the cluster, **which could be harmful**.

By default, kube-hunter does not do active hunting. To active hunt a cluster, use the `--active` flag. Example:
`kube-hunter --remote some.domain.com --active`

### List of tests
You can see the list of tests with the `--list` option: Example:
`kube-hunter --list`

To see active hunting tests as well as passive:
`kube-hunter --list --active`

### Nodes Mapping 
To see only a mapping of your nodes network, run with `--mapping` option. Example:
`kube-hunter --cidr 192.168.0.0/24 --mapping`
This will output all the Kubernetes nodes kube-hunter has found.

### Output
To control logging, you can specify a log level, using the `--log` option. Example:
`kube-hunter --active --log WARNING`
Available log levels are:

* DEBUG
* INFO (default)
* WARNING

### Dispatching
By default, the report will be dispatched to `stdout`, but you can specify different methods by using the `--dispatch` option. Example:
`kube-hunter --report json --dispatch http`
Available dispatch methods are:

* stdout (default)
* http (to configure, set the following environment variables:) 
    * KUBEHUNTER_HTTP_DISPATCH_URL (defaults to: https://localhost)
    * KUBEHUNTER_HTTP_DISPATCH_METHOD (defaults to: POST)

## Deployment
There are three methods for deploying kube-hunter:

### On Machine

You can run kube-hunter directly on your machine.

#### Prerequisites

You will need the following installed:
* python 3.x
* pip

##### Install with pip

Install:
~~~
pip install kube-hunter
~~~

Run:
~~~
kube-hunter
~~~

##### Run from source
Clone the repository:
~~~
git clone https://github.com/aquasecurity/kube-hunter.git
~~~

Install module dependencies. (You may prefer to do this within a [Virtual Environment](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/))
~~~
cd ./kube-hunter
pip install -r requirements.txt
~~~

Run:
~~~
python3 kube_hunter
~~~

_If you want to use pyinstaller/py2exe you need to first run the install_imports.py script._

### Container
Aqua Security maintains a containerized version of kube-hunter at `aquasec/kube-hunter`. This container includes this source code, plus an additional (closed source) reporting plugin for uploading results into a report that can be viewed at [kube-hunter.aquasec.com](https://kube-hunter.aquasec.com). Please note, that running the `aquasec/kube-hunter` container and uploading reports data are subject to additional [terms and conditions](https://kube-hunter.aquasec.com/eula.html).

The Dockerfile in this repository allows you to build a containerized version without the reporting plugin.

If you run kube-hunter container with the host network, it will be able to probe all the interfaces on the host:

`docker run -it --rm --network host aquasec/kube-hunter`

_Note for Docker for Mac/Windows:_ Be aware that the "host" for Docker for Mac or Windows is the VM that Docker runs containers within. Therefore specifying `--network host` allows kube-hunter access to the network interfaces of that VM, rather than those of your machine.
By default, kube-hunter runs in interactive mode. You can also specify the scanning option with the parameters described above e.g.

`docker run --rm aquasec/kube-hunter --cidr 192.168.0.0/24`

### Pod
This option lets you discover what running a malicious container can do/discover on your cluster. This gives a perspective on what an attacker could do if they were able to compromise a pod, perhaps through a software vulnerability. This may reveal significantly more vulnerabilities.

The example `job.yaml` file defines a Job that will run kube-hunter in a pod, using default Kubernetes pod access settings. (You may wish to modify this definition, for example to run as a non-root user, or to run in a different namespace.)

* Run the job with `kubectl create -f ./job.yaml`
* Find the pod name with `kubectl describe job kube-hunter`
* View the test results with `kubectl logs <pod name>`

## Contribution 
To read the contribution guidelines, <a href="https://github.com/aquasecurity/kube-hunter/blob/master/CONTRIBUTING.md"> Click here </a>

## License
This repository is available under the [Apache License 2.0](https://github.com/aquasecurity/kube-hunter/blob/master/LICENSE).
