import ssl
import logging
import base64
import re

from kube_hunter.core.pubsub.subscription import subscribe
from kube_hunter.core.types import Hunter, KubernetesCluster, InformationDisclosure, Service, Vulnerability

logger = logging.getLogger(__name__)
email_pattern = re.compile(r"([a-z0-9]+@[a-z0-9]+\.[a-z]+)")


class CertificateEmail(Vulnerability):
    """Certificate includes an email address"""

    def __init__(self, email: str):
        super().__init__(
            name="Certificate Includes Email Address",
            component=KubernetesCluster,
            category=InformationDisclosure,
            vid="KHV021",
            evidence=f"email: {email}",
        )
        self.email = email


@subscribe(Service)
class CertificateDiscovery(Hunter):
    """Certificate Email Hunting
    Checks for email addresses in kubernetes SSL certificates
    """

    def execute(self):
        try:
            logger.debug("Passive hunter is attempting to get server certificate")
            addr = (str(self.event.host), self.event.port)
            cert = ssl.get_server_certificate(addr)
        except ssl.SSLError:
            pass
        else:
            c = cert.strip(ssl.PEM_HEADER).strip(ssl.PEM_FOOTER)
            certdata = base64.b64decode(c)
            emails = re.findall(email_pattern, certdata)
            for email in emails:
                yield CertificateEmail(email=email)
