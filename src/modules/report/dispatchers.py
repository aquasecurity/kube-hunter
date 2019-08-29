import logging
import os
import requests
from __main__ import config


class HTTPDispatcher(object):
    def dispatch(self, report):
        logging.debug('Dispatching report via http')
        dispatchMethod = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_METHOD',
            'POST'
        ).upper()
        dispatchURL = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_URL',
            'https://localhost/'
        )
        try:
            r = requests.request(
                dispatchMethod,
                dispatchURL,
                json=report,
                headers={'Content-Type': 'application/json'}
            )
            r.raise_for_status()
            logging.info('\nReport was dispatched to: {url}'.format(url=dispatchURL))
            logging.debug(
                "\tResponse Code: {status}\n\tResponse Data:\n{data}".format(
                    status=r.status_code,
                    data=r.text
                )
            )
        except requests.HTTPError as e:
            # specific http exceptions
            logging.error(
                "\nCould not dispatch report using HTTP {method} to {url}\nResponse Code: {status}".format(
                    status=r.status_code,
                    url=dispatchURL,
                    method=dispatchMethod
                )
            )
        except Exception as e:
            # default all exceptions
            logging.error("\nCould not dispatch report using HTTP {method} to {url} - {error}".format(
                method=dispatchMethod,
                url=dispatchURL,
                error=e
            ))

class STDOUTDispatcher(object):
    def dispatch(self, report):
        logging.debug('Dispatching report via stdout')
        if config.report == "plain":
            logging.info("\n{div}".format(div="-" * 10))
        print(report)
