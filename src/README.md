# Guidelines for developing kube-hunter  
---  
This document is intended for developers, if you are not a developer, please refer back to the [Deployment README](/README.md)    
First, lets go through kube-hunter's basic architecture.    
### Directory Structure  
~~~  
kube-hunter/  
        plugins/  
           # your plugin
        src/  
            core/  
            modules/  
                discovery/  
                    # your module  
                hunting/  
                    # your module
                report/
                    # your module
        kube-hunter.py  
~~~  
### Design Pattern   
Kube-hunter is built with the [Observer Pattern](https://en.wikipedia.org/wiki/Observer_pattern).    
With this in mind, every new Service/Vulnerability/Information that has been discovered, will trigger a new event.   
When you write your module, you can decide on which Event to subscribe to, meaning, when exactly will your module start Hunting.  

-----------------------
### Hunter Types  
There are two hunter types which you can implement: a `Hunter` and an `ActiveHunter`.  Hunters just probe the state of a cluster, whereas ActiveHunter modules can attempt operations that could change the state of the cluster.
##### Hunter  
Example:  
~~~python  
@handler.subscribe(OpenPortEvent, predicate=lambda event: event.port == 30000)  
class KubeDashboardDiscovery(Hunter):  
    """Dashboard Discovery
    Explanation about what the hunter does
    """
    def __init__(self, event):  
        self.event = event  
    def execute(self):  
        pass  
~~~  
Kube-hunter's core module triggers your Hunter when the event you have subscribed it to occurs. 
in this example, we subscribe the Hunter, `KubeDashboardDiscovery`, to an `OpenPortEvent`, with a predicate that checks the open port (of the event) is 30000.    
`Convention:` The first line of the comment describing the hunter is the visible name, the other lines are the explanation.

   
##### ActiveHunter  
An ActiveHunter will be subscribed to events (and therefore operate) only if kube-hunter is running in active scanning mode.  
Implementing an Active Hunter is the same as implementing a regular Hunter, you just need to inherit from `ActiveHunter`  
Example:   
```python  
class ProveSomeVulnerability(ActiveHunter):  
...  
```  
#### **Absolutely important to notice:**  

* Every hunter, needs to implement an `execute` method. the core module will execute this method automatically.
* Every hunter, needs to save its given event from the `__init__` in it's attributes.  
* When subscribing to an event, if a `predicate` is specified, it will be called with the event itself, pre trigger.  
* When inheriting from `Hunter` or `ActiveHunter` you can use the `self.publish_event(event)`.  
 `event` is an **initialized** event object  
  
-----------------------

## Creating The Module
The first step is to create a new file in the `hunting` or the `discovery` folder.  
_The file's (module's) content is imported automatically"_  
`Convention:` Hunters which discover a new service should be placed under the `discovery` folder.
`Convention:` Hunters which discover a new vulnerability, should be placed under the `hunting` folder.
`Convention:` Hunters which use vulnerabilities, should be placed under the `hunting` folder and should implement the ActiveHunter base class.
  
The second step is to determine what events your Hunter will subscribe to, and from where you can get them.  
`Convention:` Events should be declared in their corresponding module. for example, a KubeDashboardEvent event is declared in the dashboard discovery module.  
     
Following the above example, let's figure out the imports:  
```python  
from ...core.types import Hunter  
from ...core.events import handler  
  
from ...core.events.types import OpenPortEvent  
  
@handler.subscribe(OpenPortEvent, predicate=lambda event: event.port == 30000)  
class KubeDashboardDiscovery(Hunter):  
    def __init__(self, event):  
        self.event = event  
    def execute(self):  
        pass  
```  
As you can see, all of the types here come from the `core` module. 
  
### Core Imports  
relative import: `...core.events`  

|Name|Description|
|---|---|
|handler|Core object for using events, every module should import this object|

relative import `...core.events.types`  

|Name|Description|
|---|---|
|Service|Base class for defining a new Service|
|Vulnerability|Base class for defining a new vulnerability|
|OpenPortEvent|Published when a new port is discovered. open port is assigned to the `port ` attribute|
  
relative import: `...core.types`  

|Type|Description|
|---|---|
|Hunter|Regular Hunter|
|ActiveHunter|Active Hunter|
|KubernetesCluster|Component class, used on creation of vulnerabilities, to specify category|
|Kubelet|Component class, used on creation of vulnerabilities, to specify category|
  
  
## Creating Events  
As discussed above, we know there are alot of different types of events that can be created. but at the end, they all need to inherit from the base class `Event`  
lets see some examples of creating different types of events:  
### Vulnerability  
```python  
class ExposedMasterCN(Vulnerability, Event):  
    """Explanation about this vulnerability and what it can do when exploited"""  
    def __init__(self, master_ip):  
        Vulnerability.__init__(self, component=KubernetesCluster, name="Master Exposed From Certificate", category=InformationDisclosure)
        self.evidence = master_ip
```  
  
### Service  
```python  
class OpenKubeDns(Service, Event):  
    """Explanation about this Service"""  
    def __init__(self):  
        Service.__init__(self, name="Kube-Dns")  
```  
`Notice:` Every type of event, should have an explanation in exactly the form shown above, that explanation will eventually be used when the report is made.  
`Notice:` You can add any attribute to the event you create as needed, the examples shown above is the minimum implementation that needs to be made  
  
----------------------- 
## Events 
`Internals Note:` In kube-hunter, each published event gets all the attributes from the previous event that has been used by its publisher (Hunter). This process is invisible, and happens on the core module, without worrying the developer. 
Accordingly, we can look at events as individual trees that remember their past attributes, and gives us access to them.    
  
#### The event chain  
Example for an event chain:  
`NewHostEvent -> OpenPortEvent -> KubeProxyEvent -> KubeDashboard -> K8sVersionDisclosure`  
*The first node of every event tree is the NewHostEvent*  
  
Let us assume the following imaginary example: 
We've defined a Hunter for SSL Certificates, which extracts the CN of the certificate, and does some magic with it. The example code would be defined in new `discovery` and `hunter` modules for this SSL Magic example:    

Discovery:  
```python  
class NewSslCertificate(Event):  
    def __init__(self, certificate):  
        self.certificate = certificate 

@handler.subscribe(KubeProxyEvent) 
class SslDiscover(Hunter):  
    def __init__(self, event):  
        self.event = event  
    def execute(self):  
        self.publish_event( NewSslCertificate(certificate=get_cert()) )  
```  
Hunting:  
```python  
@handler.subscribe(NewSslCertificate)  
class SslHunter(Hunter):  
    def __init__(self, event):  
        self.event = event  
    def execute(self):  
        do_magic(self.event.certificate)  
```  
Let's say we now want to do something with the hostname from the certificate from. In the event tree, we can check if the host attribute was assigned to our event previously, by directly accessing `event.host`. If it has not been specified from some reason, the value is `None`. 
So this is sufficient for our example:
```python  
...
def execute(self):  
    do_magic(self.event.certificate)  
    do_something_with_host(self.event.host) # normal access  
```  

If another Hunter subscribes to the events that this Hunter publishes, if can  access the `event.certificate`.
  
## Proving Vulnerabilities  
The process of proving vulnerabilities, is the base concept of the Active Hunting.    
To prove a vulnerability, create an `ActiveHunter` that is subscribed to the vulnerability, and inside of the `execute`, specify the `evidence` attribute of the event.   
*Note that you can specify the 'evidence' attribute without active hunting*  
