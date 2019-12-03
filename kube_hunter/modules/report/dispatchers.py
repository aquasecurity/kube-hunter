import logging
import os
import requests

from kube_hunter.conf import config


class HTTPDispatcher(object):
    def dispatch(self, report):
        logging.debug('Dispatching report via http')
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
            logging.info('\nReport was dispatched to: {url}'.format(url=dispatch_url))
            logging.debug(
                "\tResponse Code: {status}\n\tResponse Data:\n{data}".format(
                    status=r.status_code,
                    data=r.text
                )
            )
        except requests.HTTPError as e:
            # specific http exceptions
            logging.exception(
                "\nCould not dispatch report using HTTP {method} to {url}\nResponse Code: {status}".format(
                    status=r.status_code,
                    url=dispatch_url,
                    method=dispatch_method
                )
            )
        except Exception as e:
            # default all exceptions
            logging.exception("\nCould not dispatch report using HTTP {method} to {url}".format(
                method=dispatch_method,
                url=dispatch_url
            ))

class STDOUTDispatcher(object):
    def dispatch(self, report):
        logging.debug('Dispatching report via stdout')
        if config.report == "plain":
            logging.info("\n{div}".format(div="-" * 10))
        print(report)
