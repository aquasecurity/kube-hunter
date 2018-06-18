# Guidelines for developing Kube Hunter  
---  
This document is intended for developers, if you are not a developer, please refer back to the [Deployment README](/README.md)    
First, lets go through Kube Hunter's basic architecture.    
### Directory Structure  
~~~  
kube-hunter/  
        log/  
        src/  
            core/  
            modules/  
                discovery/  
                    # your module  
                hunting/  
                    # your module  
        kube-hunter.py  
~~~  
### Design Pattern   
Kube Hunter is built with the [Observer Pattern](https://en.wikipedia.org/wiki/Observer_pattern).    
With this in mind, every new Service/Vulnerability/Information that has been discovered, will trigger a new event.   
When you write your module, you can decide on which Event to subscribe to. meaning, when exactly will your module start Hunting.  

-----------------------
### Hunter Types  
There are two hunter types which you can implement. a `Hunter` and an `ActiveHunter`.  
##### Hunter  
Example:  
~~~python  
@handler.subscribe(OpenPortEvent, predicate=lambda event: event.port == 30000)  
class KubeDashboardDiscovery(Hunter):  
    def __init__(self, event):  
        self.event = event  
    def execute(self):  
        pass  
~~~  
Kube Hunter's core module is taking care of trigerring your hunter by your demands.    
in this example, we subscribe the Hunter, `KubeDashboardDiscovery`, to an `OpenPortEvent`, with a predicate that checks the open port (of the event) is 30000.    
   
##### ActiveHunter  
An active hunter will be subscribed only if an active scanning is in place.  
Implementing an Active Hunter, is the same as implementing a regular Hunter, you just need to inherint from `ActiveHunter`  
Example:   
```python  
class ProveSomeVulnerability(ActiveHunter):  
...  
```  
#### **Absolutely important to notice:**  
* every hunter, needs to implement an `execute` method. the core module will execute this method automatically  
* every hunter, needs to save its given event from the `__init__` in it's attributes.  
* when subscribing to an event, if a `predicate` is specified, it will be called with the event itself, pre trigger.  
* When inheriting from `Hunter` or `ActiveHunter` you can use the `self.publish_event(event)`.  
 `event` is an **initialized** event object  
  
-----------------------
## Creating The Module    
The first step, is to create a new file in the hunting or the discovery folders.    
`Convention:` Hunters which discovers a new service should be placed under the discovery/ folder    
`Convention:` Hunters which discovers a new vulnerability, should be placed under the hunting/ folder              
     
The second step, is to determine what events your Hunter will subscribe to, and from where you can get them.  
`Convention:` Events should be declared in their corresponding module. for example, an KubeDashboardEvent event is declared in the dashboard discovery module.  
     
Following the above example, lets figure out the imports:  
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
As you can see, all of the types here comes from the `core` module. let us list them:  
  
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
    def __init__(self):  
        Vulnerability.__init__(self, component=KubernetesCluster, name="Master Exposed From Certificate")  
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

----------------------- 
## Events Magic  
`Internals Note:` In Kube Hunter, each event that's getting published, gets all the attributes from the previous event that has been used by it's publisher (Hunter). This process is invisible, and happens on the core module, without worrying the developer.    
According to this note, we can look at events as individual trees that remembers their past attributes, and gives us access to them.    
  
#### the event chain  
Example for an event chain:  
`NewHostEvent -> OpenPortEvent -> KubeProxyEvent -> KubeDashboard -> K8sVersionDisclosure`  
*The first node of every event tree is the NewHostEvent*  
  
Let us assume the following imaginary example:    
We've defined a Hunter for SSL Certificates, which extracts the CN of the certificate, and is doing some magic with it.    
imagine this was defined on modules of your creating:    
--  
Discovery:  
```python  
class NewSslCertificate(Event):  
    def __init__(self, certificate):  
        self.certificate = certificate  
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
lets say we now want to do something with the hostname from which we found the certificate from, from the event tree, we can check if the host attribute was assigned to our event previously, by directly accessing `event.host`.    
if it has not been specified from some reason, the value is `None`.    
So a simple:    
```python  
...  
def execute(self):  
    do_magic(self.event.certificate)  
    do_something_with_host(self.event.host) # normal access  
```  
will do.    
For the same reasons, the next hunter that will receive some event that this hunter published, could access the `event.certificate`.    
  
## Proving Vulnerabilities  
The process of proving vulnerabilities, is the base concept of the Active Hunting.    
To prove a vulnerability, create an `ActiveHunter` that is subscribed to the vulnerability, and inside of the `execute`, specify the `evidence` attribute of the event.  
  
