import ssl
import logging
import base64
import re

from kube_hunter.core.types import Hunter, KubernetesCluster, InformationDisclosure
from kube_hunter.core.events import handler
from kube_hunter.core.events.types import Vulnerability, Event, Service

logger = logging.getLogger(__name__)
email_pattern = re.compile(rb"([a-z0-9]+@[a-z0-9]+\.[a-z0-9]+)")


class CertificateEmail(Vulnerability, Event):
    """Certificate includes an email address"""

    def __init__(self, email):
        Vulnerability.__init__(
            self,
            KubernetesCluster,
            "Certificate Includes Email Address",
            category=InformationDisclosure,
            vid="KHV021",
        )
        self.email = email
        self.evidence = f"email: {self.email}"


@handler.subscribe(Service)
class CertificateDiscovery(Hunter):
    """Certificate Email Hunting
    Checks for email addresses in kubernetes ssl certificates
    """

    def __init__(self, event):
        self.event = event

    def execute(self):
        try:
            logger.debug("Passive hunter is attempting to get server certificate")
            addr = (str(self.event.host), self.event.port)
            cert = ssl.get_server_certificate(addr)
        except ssl.SSLError:
            # If the server doesn't offer SSL on this port we won't get a certificate
            return
        self.examine_certificate(cert)

    def examine_certificate(self, cert):
        c = cert.strip(ssl.PEM_HEADER).strip("\n").strip(ssl.PEM_FOOTER).strip("\n")
        certdata = base64.b64decode(c)
        emails = re.findall(email_pattern, certdata)
        for email in emails:
            self.publish_event(CertificateEmail(email=email))
