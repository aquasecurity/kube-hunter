# Guidelines for developing kube-hunter  
---  
This document is intended for developers, if you are not a developer, please refer back to the [Deployment README](/README.md)    
First, let's go through kube-hunter's basic architecture.    
### Directory Structure  
~~~  
kube-hunter/  
        kube_hunter/  
            core/  
            modules/  
                discovery/  
                    # your module  
                hunting/  
                    # your module
                report/
                    # your module
            __main__.py  
~~~  
### Design Pattern   
Kube-hunter is built with the [Observer Pattern](https://en.wikipedia.org/wiki/Observer_pattern).    
With this in mind, every new Service/Vulnerability/Information that has been discovered will trigger a new event.   
When you write your module, you can decide on which Event to subscribe to, meaning, when exactly will your module start Hunting.  

-----------------------
### Hunter Types  
There are three hunter types which you can implement: a `Hunter`, `ActiveHunter` and `Discovery`. Hunters just probe the state of a cluster, whereas ActiveHunter modules can attempt operations that could change the state of the cluster. Discovery is Hunter for discovery purposes only.
##### Hunter  
Example:  
~~~python  
@handler.subscribe(OpenPortEvent, predicate=lambda event: event.port == 30000)  
class KubeDashboardDiscovery(Hunter):  
    """Dashboard Discovery
    Explanation about what the Hunter does
    """
    def __init__(self, event):  
        self.event = event  
    def execute(self):  
        pass  
~~~  
Kube-hunter's core module triggers your Hunter when the event you have subscribed it to occurs. 
In this example, we subscribe the Hunter, `KubeDashboardDiscovery`, to an `OpenPortEvent`, with a predicate that checks the open port (of the event) is 30000.
`Convention:` The first line of the comment describing the Hunter is the visible name, the other lines are the explanation.

   
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
* When subscribing to an event, if a `predicate` is specified, it will be called with the event itself, pre-trigger.  
* When inheriting from `Hunter` or `ActiveHunter` you can use the `self.publish_event(event)`.  
 `event` is an **initialized** event object.
  
-----------------------

## Creating The Module
The first step is to create a new file in the `hunting` or the `discovery` folder.  
_The file's (module's) content is imported automatically"_  
`Convention:` Hunters which discover a new service should be placed under the `discovery` folder.
`Convention:` Hunters which discover a new vulnerability should be placed under the `hunting` folder.
`Convention:` Hunters which use vulnerabilities should be placed under the `hunting` folder and should implement the ActiveHunter base class.
  
The second step is to determine what events your Hunter will subscribe to, and from where you can get them.  
`Convention:` Events should be declared in their corresponding module. For example, a KubeDashboardEvent event is declared in the dashboard discovery module.
     
 `Note:` A Hunter located under the `discovery` folder should not import any modules located under the `hunting` folder
in order to prevent circular dependency bug.

Following the above example, let's figure out the imports:  
```python  
from kube_hunter.core.types import Hunter  
from kube_hunter.core.events.event_handler import handler  
  
from kube_hunter.core.events.types import OpenPortEvent  
  
@handler.subscribe(OpenPortEvent, predicate=lambda event: event.port == 30000)  
class KubeDashboardDiscovery(Hunter):  
    def __init__(self, event):  
        self.event = event  
    def execute(self):  
        pass  
```  
As you can see, all of the types here come from the `core` module. 
  
### Core Imports  
Absolute import: `kube_hunter.core.events`  

|Name|Description|
|---|---|
|handler|Core object for using events, every module should import this object|

Absolute import `kube_hunter.core.events.types`  

|Name|Description|
|---|---|
|Service|Base class for defining a new Service|
|Vulnerability|Base class for defining a new vulnerability|
|OpenPortEvent|Published when a new port is discovered. open port is assigned to the `port ` attribute|
  
Absolute import: `kube_hunter.core.types`  

|Type|Description|
|---|---|
|Hunter|Regular Hunter|
|ActiveHunter|Active Hunter|
|KubernetesCluster|Component class, used on creation of vulnerabilities, to specify category|
|Kubelet|Component class, used on creation of vulnerabilities, to specify category|
  
  
## Creating Events  
As discussed above, we know there are a lot of different types of events that can be created. but at the end, they all need to inherit from the base class `Event`  
Let's see some examples of creating different types of events:  
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
        Service.__init__(self, name="Kube-DNS")  
```  
`Notice:` Every type of event should have an explanation in exactly the form shown above (that explanation will eventually be used when the report is made).
`Notice:` You can add any attribute to the event you create as needed. The examples shown above are the minimum implementation that needs to be made.
  
----------------------- 
## Events 
`Internals Note:` In kube-hunter, each published event gets all the attributes from the previous event that has been used by its publisher (Hunter). This process is invisible, and happens on the core module, without worrying the developer. 
Accordingly, we can look at events as individual trees that remember their past attributes, and gives us access to them.    
  
#### The event chain  
Example for an event chain:  
`NewHostEvent -> OpenPortEvent -> KubeProxyEvent -> KubeDashboard -> K8sVersionDisclosure`  
*The first node of every event tree is the NewHostEvent*  
  
Let us assume the following imaginary example: 
We've defined a Hunter for SSL Certificates, which extracts the CN of the certificate and does some magic with it. The example code would be defined in new `discovery` and `hunter` modules for this SSL Magic example:    

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
Let's say we now want to do something with the hostname from the certificate. In the event tree, we can check if the host attribute was assigned to our event previously, by directly accessing `event.host`. If it has not been specified for some reason, the value is `None`. So this is sufficient for our example:
```python  
...
def execute(self):  
    do_magic(self.event.certificate)  
    do_something_with_host(self.event.host) # normal access  
```  

If another Hunter subscribes to the events that this Hunter publishes, it can access the `event.certificate`.
  
## Proving Vulnerabilities  
The process of proving vulnerabilities is the base concept of Active Hunting.    
To prove a vulnerability, create an `ActiveHunter` that is subscribed to the vulnerability, and inside of the `execute`, specify the `evidence` attribute of the event.   
*Note that you can specify the 'evidence' attribute without active hunting*  

## Filtering Events
A filter can change an event's attribute or remove it completely before it gets published to Hunters.

To create a filter:
* create a class that inherits from `EventFilterBase` (from `kube_hunter.core.events.types`)   
* use `@handler.subscribe(Event)` to filter a specific `Event`
* define a `__init__(self, event)` method, and save the event in your class  
* implement `self.execute(self)` method, __returns a new event, or None to remove event__  
_(You can filter a parent event class, such as Service or Vulnerability, to filter all services/vulnerabilities)_
  
#### Options for filtering:  
* Remove/Prevent an event from being published 
* Altering event attributes 
  
To prevent an event from being published, return `None` from the execute method of your filter.  
To alter event attributes, return a new event, based on the `self.event` after your modifications, it will replace the event itself before it is published.  
__Make sure to return the event from the execute method, or the event will not get published__  
 
For example, if you don't want to hunt services found on a localhost IP, you can create the following module, in the `kube_hunter/modules/report/`
```python
from kube_hunter.core.events.event_handler import handler
from kube_hunter.core.events.types import Service, EventFilterBase

@handler.subscribe(Service)
class LocalHostFilter(EventFilterBase):
    # return None to filter out event
    def execute(self):
        if self.event.host == "127.0.0.1":
            return None
        return self.event
```
The following filter will filter out any Service found on a localhost IP. Those Services will not get published to Kube-Hunter's Queue.
That means other Hunters that are subscribed to this Service will not get triggered.
That opens up a wide variety of possible operations, as this not only can __filter out__ events, but you can actually __change event attributes__, for example:

```python
from kube_hunter.core.events.event_handler import handler
from kube_hunter.core.types import InformationDisclosure
from kube_hunter.core.events.types import Vulnerability, EventFilterBase

@handler.subscribe(Vulnerability)
class CensorInformation(EventFilterBase):
    # return None to filter out event
    def execute(self):
        if self.event.category == InformationDisclosure:
            new_event = self.event
            new_event.evidence = "<classified information>"
            return new_event
        else:
            return self.event
```
This will censor all vulnerabilities which can disclose information about a cluster. 

__Note: In filters, you should not change attributes in the event.previous. This will result in unexpected behaviour__.

## Tests
Although we haven't been rigorous about this in the past, please add tests to support your code changes. Tests are executed like this: 

```bash
pytest
```
