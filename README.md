# Kube Hunter
---
Kube Hunter hunts for security weaknesses in Kubernetes clusters. The tool was developed to increase awareness and visibility for security issues in Kubernetes environments.
  
We welcome contributions, especially new hunter modules that perform additional tests. If you would like to develop your own modules please read [Guidelines For Developing Your First Kube Hunter Module](src/README.md).

## Hunting

By default, without any special flags, Kube Hunter will open an interactive session, in which you will be able to select one of its scan options.   
If you want to specify the scan option manually, form the command line. these are your options:  

To specify a specific cidr to scan, use the `--cidr` option. Example:  
`./kube-hunter.py --cidr 192.168.0.0/24`  
  
To specify remote machines for hunting, you can use the `--remote` option. Example:  
`./kube-hunter.py --remote some.node.com`  

To specify internal scanning, you can use the `--internal` option. (this will scan all of the machine's network interfaces) Example:  
`./kube-hunter.py --internal`  


### Active Hunting

Active hunting is an option in which Kube Hunter will exploit vulnerabilities it finds, in order to explore for further vulnerabilities.
The main difference between normal and active hunting is that a normal hunt will never change state of the cluster, while active hunting can potentially do state-changing and harmful operations on the cluster.
To active hunt a cluster, use the `--active` flag. Example:  
`./kube-hunter.py --remote some.domain.com --active`  

### Output
To control logging, you can specify a log level, using the `--log` option. Example:  
`./kube-hunter.py --active --log WARNING`  
Available log levels are: 

* DEBUG  
* INFO (default)  
* WARNING
  
To see only a mapping of your nodes network, run with `--mapping` option. Example:  
`./kube-hunter.py --cidr 192.168.0.0/24 --mapping`  
This will output all the Kubernetes nodes Kube Hunter has found.

## Deployment

There are three methods for deploying Kube Hunter:  
### On Machine
***
#### Installation
##### Requirements:

* python 2.7  
* pip  

Installing modules:  
~~~
cd ./kube-hunter
pip install -r requirements.txt
~~~
Running:  
`./kube-hunter.py`

### Container
***
To run Kube Hunter as a container:

**Linux:**  
`docker run --rm --network host aquasec/kube-hunter`  
**Windows/Mac:**   
`docker run --rm aquasec/kube-hunter --cidr 192.168.0.0/24`  

_Note for Docker for Mac/Windows:_ You'll need to specify the CIDR because of the VM that Docker for Mac/Windows runs in.

### Pod
***
This option lets you discover what running a malicious container can do/discover on your cluster.  
Kube Hunter will scan your cluster from the inside, using default Kubernetes pod access settings. This may reveal significantly more vulnerabilities. 
To run Kube Hunter as a pod, `kubectl create` the following yaml file.  
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
  restartPolicy: Never   # for Kube Hunter to hunt once
~~~
