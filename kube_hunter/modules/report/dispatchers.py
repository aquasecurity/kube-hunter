import logging
import os
import requests

from kube_hunter.conf import config

logger = logging.getLogger(__name__)


class HTTPDispatcher(object):
    def dispatch(self, report):
        logger.debug('Dispatching report via http')
        dispatch_method = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_METHOD',
            'POST'
        ).upper()
        dispatch_url = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_URL',
            'https://localhost/'
        )
        try:
            r = requests.request(
                dispatch_method,
                dispatch_url,
                json=report,
                headers={'Content-Type': 'application/json'}
            )
            r.raise_for_status()
            logger.info(f'\nReport was dispatched to: {dispatch_url}')
            logger.debug(f"\tResponse Code: {r.status_code}\n\tResponse Data:\n{r.text}")

        except requests.HTTPError as e:
            # specific http exceptions
            logger.exception(f"\nCould not dispatch report using HTTP {dispatch_method} to "
                             f"{dispatch_url}\n"
                             f"Response Code: {r.status_code}")
        except Exception as e:
            # default all exceptions
            logger.exception(f"\nCould not dispatch report using HTTP {dispatch_method} to {dispatch_url}")


class STDOUTDispatcher(object):
    def dispatch(self, report):
        logger.debug('Dispatching report via stdout')
        print(report)
