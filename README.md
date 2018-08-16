# Kube-hunter
---
Kube-hunter hunts for security weaknesses in Kubernetes clusters. The tool was developed to increase awareness and visibility for security issues in Kubernetes environments. **You should NOT run kube-hunter on a Kubernetes cluster you don't own!**

**Run Kube Hunter**: Kube-hunter is available as a container (aquasec/kube-hunter), and we also offer a web site at [kube-hunter.aquasec.com](https://kube-hunter.aquasec.com) where you can register online to receive a token allowing you see and share the results online. You can also run the Python code yourself as described below.  
  
**Contribute**: We welcome contributions, especially new hunter modules that perform additional tests. If you would like to develop your own modules please read [Guidelines For Developing Your First Kube-hunter Module](src/README.md).

## Hunting

### Where should I run kube-hunter?
Run kube-hunter on any machine (including your laptop), select Remote scanning and give the IP address or domain name of your Kubernetes cluster. This will give you an attackers-eye-view of your Kubernetes setup. 

You can run kube-hunter directly on a machine in the cluster, and select the option to probe all the local network interfaces. 

You can also run kube-hunter as a pod within the cluster. This gives an indication of how exposed your cluster would be in the event that one of your application pods is compromised (through a software vulnerability, for example). 

### Scanning options
By default, kube-hunter will open an interactive session, in which you will be able to select one of the following scan options. You can also specify the scan option manually from the command line. These are your options:  

1. **Remote scanning**
To specify remote machines for hunting, select option 1 or use the `--remote` option. Example:  
`./kube-hunter.py --remote some.node.com`  

2. **Internal scanning**
To specify internal scanning, you can use the `--internal` option. (this will scan all of the machine's network interfaces) Example:  
`./kube-hunter.py --internal`  

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
  
### Output
To control logging, you can specify a log level, using the `--log` option. Example:  
`./kube-hunter.py --active --log WARNING`  
Available log levels are: 

* DEBUG  
* INFO (default)  
* WARNING
  
To see only a mapping of your nodes network, run with `--mapping` option. Example:  
`./kube-hunter.py --cidr 192.168.0.0/24 --mapping`  
This will output all the Kubernetes nodes kube-hunter has found.

## Deployment
There are three methods for deploying kube-hunter:
 
### On Machine

You can run the kube-hunter python code directly on your machine. 
#### Prerequisites

You will need the following installed:
* python 2.7  
* pip  

Clone the repository:
~~~
git clone git@github.com:aquasecurity/kube-hunter.git
~~~

Install module dependencies:  
~~~
cd ./kube-hunter
pip install -r requirements.txt
~~~
Run:  
`./kube-hunter.py`

### Container
Aqua Security maintains a containerised version of kube-hunter at `aquasec/kube-hunter`. This container includes this source code, plus some additional code for uploading results into a report that can be viewed at [kube-hunter.aquasec.com](https://kube-hunter.aquasec.com). 

If you run the kube-hunter container with the host network it will be able to probe all the interfaces on the host: 

`docker run -it --rm --network host aquasec/kube-hunter`  

_Note for Docker for Mac/Windows:_ Be aware that the "host" for Docker for Mac or Windows is the VM which Docker runs containers within. Therefore specifying `--network host` allows kube-hunter access to the network interfaces of that VM, rather than those of your laptop.  
By default kube-hunter runs in interactive mode. You can also specify the scanning option with the parameters described above e.g. 

`docker run --rm aquasec/kube-hunter --cidr 192.168.0.0/24`  

### Pod
This option lets you discover what running a malicious container can do/discover on your cluster. This gives a perspective on what an attacker could do if they were able to compromise a pod, perhaps through a software vulnerability. 

Kube-hunter will scan your cluster from the inside, using default Kubernetes pod access settings. This may reveal significantly more vulnerabilities. 
To run kube-hunter as a pod, `kubectl create` the following yaml file.  
~~~
---
apiVersion: v1
kind: Pod
metadata:
  name: kube-hunter
spec:
  containers:
  - name: kube-hunter
    image: aquasec/kube-hunter
    command: ["python", "kube-hunter.py"]
    args: ["--pod"]
  restartPolicy: Never   # for kube-hunter to hunt once
~~~
