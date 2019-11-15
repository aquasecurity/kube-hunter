---
---
# Welcome to kube-hunter documentation

## Documentation for vulnerabilities

For information about a specific vulnerability reported by kube-hunter, enter its 'VID' (e.g. KHV004) in the search box to the left, to get to the vulnerability article.

For a complete list of all documented vulnerabilities, [click here]({{ site.baseurl }}{% link kbindex.html %})

## Getting started

### Where should I run kube-hunter?
Run kube-hunter on any machine (including your laptop), select Remote scanning and give the IP address or domain name of your Kubernetes cluster. This will give you an attackers-eye-view of your Kubernetes setup.

You can run kube-hunter directly on a machine in the cluster, and select the option to probe all the local network interfaces.

You can also run kube-hunter in a pod within the cluster. This gives an indication of how exposed your cluster would be in the event that one of your application pods is compromised (through a software vulnerability, for example).

### Scanning options

By default, kube-hunter will open an interactive session, in which you will be able to select one of the following scan options. You can also specify the scan option manually from the command line. These are your options:

1. **Remote scanning**
To specify remote machines for hunting, select option 1 or use the `--remote` option. Example:
`./kube-hunter.py --remote some.node.com`

2. **interface scanning**
To specify interface scanning, you can use the `--interface` option. (this will scan all of the machine's network interfaces) Example:
`./kube-hunter.py --interface`

3. **Network scanning**
To specify a specific CIDR to scan, use the `--cidr` option. Example:
`./kube-hunter.py --cidr 192.168.0.0/24`

### Active Hunting

Active hunting is an option in which kube-hunter will exploit vulnerabilities it finds, in order to explore for further vulnerabilities.
The main difference between normal and active hunting is that a normal hunt will never change state of the cluster, while active hunting can potentially do state-changing operations on the cluster, **which could be harmful**.

By default, kube-hunter does not do active hunting. To active hunt a cluster, use the `--active` flag. Example:
`./kube-hunter.py --remote some.domain.com --active`

### List of tests
You can see the list of tests with the `--list` option: Example:
`./kube-hunter.py --list`

To see active hunting tests as well as passive:
`./kube-hunter.py --list --active`

### Nodes Mapping 
To see only a mapping of your nodes network, run with `--mapping` option. Example:
`./kube-hunter.py --cidr 192.168.0.0/24 --mapping`
This will output all the Kubernetes nodes kube-hunter has found.

### Output
To control logging, you can specify a log level, using the `--log` option. Example:
`./kube-hunter.py --active --log WARNING`
Available log levels are:

* DEBUG
* INFO (default)
* WARNING

### Dispatching
By default, the report will be dispatched to `stdout`, but you can specify different methods, by using the `--dispatch` option. Example:
`./kube-hunter.py --report json --dispatch http`
Available dispatch methods are:

* stdout (default)
* http (to configure, set the following environment variables:) 
    * KUBEHUNTER_HTTP_DISPATCH_URL (defaults to: https://localhost)
    * KUBEHUNTER_HTTP_DISPATCH_METHOD (defaults to: POST)

## Deployment
There are three methods for deploying kube-hunter:

### On Machine

You can run the kube-hunter python code directly on your machine.
#### Prerequisites

You will need the following installed:
* python 3.x
* pip

Clone the repository:
~~~
git clone https://github.com/aquasecurity/kube-hunter.git
~~~

Install module dependencies:
~~~
cd ./kube-hunter
pip install -r requirements.txt
~~~

Run:
`./kube-hunter.py`

_If you want to use pyinstaller/py2exe you need to first run the install_imports.py script._
### Container
Aqua Security maintains a containerised version of kube-hunter at `aquasec/kube-hunter`. This container includes this source code, plus an additional (closed source) reporting plugin for uploading results into a report that can be viewed at [kube-hunter.aquasec.com](https://kube-hunter.aquasec.com). Please note that running the `aquasec/kube-hunter` container and uploading reports data are subject to additional [terms and conditions](https://kube-hunter.aquasec.com/eula.html).

The Dockerfile in this repository allows you to build a containerised version without the reporting plugin.

If you run the kube-hunter container with the host network it will be able to probe all the interfaces on the host:

`docker run -it --rm --network host aquasec/kube-hunter`

_Note for Docker for Mac/Windows:_ Be aware that the "host" for Docker for Mac or Windows is the VM which Docker runs containers within. Therefore specifying `--network host` allows kube-hunter access to the network interfaces of that VM, rather than those of your machine.
By default kube-hunter runs in interactive mode. You can also specify the scanning option with the parameters described above e.g.

`docker run --rm aquasec/kube-hunter --cidr 192.168.0.0/24`

### Pod
This option lets you discover what running a malicious container can do/discover on your cluster. This gives a perspective on what an attacker could do if they were able to compromise a pod, perhaps through a software vulnerability. This may reveal significantly more vulnerabilities.

The `job.yaml` file defines a Job that will run kube-hunter in a pod, using default Kubernetes pod access settings.
* Run the job with `kubectl create` with that yaml file.
* Find the pod name with `kubectl describe job kube-hunter`
* View the test results with `kubectl logs <pod name>`
