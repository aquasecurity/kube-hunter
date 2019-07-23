import logging
import requests
import json
import threading
from src.core.types import InformationDisclosure, DenialOfService, RemoteCodeExec, IdentityTheft, PrivilegeEscalation, AccessRisk, UnauthenticatedAccess

class EventFilterBase(object):
    def __init__(self, event):
        self.event = event

    # Returns self.event as default.
    # If changes has been made, should return the new event that's been altered
    # Return None to indicate the event should be discarded
    def execute(self):
        return self.event

class Event(object):
    def __init__(self):
        self.previous = None
        self.hunter = None

    # newest attribute gets selected first
    def __getattr__(self, name):
        if name == "previous":
            return None
        for event in self.history:
            if name in event.__dict__:
                return event.__dict__[name]

    # Event's logical location to be used mainly for reports.
    # If event don't implement it check previous event
    # This is because events are composed (previous -> previous ...)
    # and not inheritted 
    def location(self):
        location = None
        if self.previous:
            location = self.previous.location()

        return location

    # returns the event history ordered from newest to oldest
    @property
    def history(self):
        previous, history = self.previous, list()
        while previous:
            history.append(previous)
            previous = previous.previous
        return history


""" Event Types """
# TODO: make proof an abstract method.


class Service(object):
    def __init__(self, name, path="", secure=True):
        self.name = name
        self.secure = secure
        self.path = path
        self.role = "Node"

    def get_name(self):
        return self.name

    def get_path(self):
        return "/" + self.path if self.path else ""

    def explain(self):
        return self.__doc__


class Vulnerability(object):
    severity = dict({
        InformationDisclosure: "medium",
        DenialOfService: "medium",
        RemoteCodeExec: "high",
        IdentityTheft: "high",
        PrivilegeEscalation: "high",
        AccessRisk: "low",
        UnauthenticatedAccess: "low"
    })

    def __init__(self, component, name, category=None):
        self.component = component
        self.category = category
        self.name = name
        self.evidence = ""
        self.role = "Node"

    def get_category(self):
        if self.category:
            return self.category.name

    def get_name(self):
        return self.name

    def explain(self):
        return self.__doc__

    def get_severity(self):
        return self.severity.get(self.category, "low")

global event_id_count_lock
event_id_count_lock = threading.Lock()
event_id_count = 0

""" Discovery/Hunting Events """


class NewHostEvent(Event):
    def __init__(self, host, cloud=None):
        global event_id_count
        self.host = host
        self.cloud = cloud
        event_id_count_lock.acquire()
        self.event_id = event_id_count
        event_id_count += 1
        event_id_count_lock.release()

    def __str__(self):
        return str(self.host)
    
    # Event's logical location to be used mainly for reports.
    def location(self):
        return str(self.host)

class OpenPortEvent(Event):
    def __init__(self, port):
        self.port = port
    
    def __str__(self):
        return str(self.port)
    
    # Event's logical location to be used mainly for reports.
    def location(self):
        if self.host:
            location = str(self.host) + ":" + str(self.port)
        else:
            location = str(self.port)
        return location

class HuntFinished(Event):
    pass


class HuntStarted(Event):
    pass
