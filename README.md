# Kube Hunter
---
Kube Hunter is an open source tool maintained by Aqua Security, which hunts weak kubernetes clusters.  
The tool was developed to increase awareness and visibility for security issues in Kubernetes environments,  
  
_Developers, please read [Guidelines For Developing Your First Kube Hunter Module](URL)_  
## Hunting  
by default, without any special flags, Kube Hunter will scan all of your machine's network interfaces for open kubernetes services.   

To specify a specific cidr to scan, use the `--cidr` option. Example:  
`./kube-hunter.py --cidr 192.168.0.0/24`  
  
To specify remote machines for hunting, you can use the `--remote` option. Example:  
`./kube-hunter.py --remote some.domain.com`  
  
To see other options:    
`./kube-hunter.py -h`  
  
There are three methods in which you can run Kube Hunter with:  
### On Machine
***
#### Installation
##### Requirements:
* python 2.7  
* pip  

Installing modules  
~~~
cd ./kube-hunter
pip install -r requirements.txt
~~~
Running:  
`./kube-hunter.py`

### Container
***
To run Kube Hunter's container:

**running on Linux:**  
`docker run --rm --network host aquasec/kube-hunter`  
**running on Windows:**   
`docker run --rm aquasec/kube-hunter --cidr 192.168.0.0/24`  

_Docker for Windows forces us to use a manual cidr, as to it's limitations_
### Pod
***
This option lets you discover what running a malicous container can do/discover on your cluster.  
Kube Hunter will scan your cluster from the inside, revealing more   
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
~~~
