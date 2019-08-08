import logging
import os
import requests
from __main__ import config


class HTTPDispatcher(object):
    def dispatch(self, report):
        logging.info('Dispatching report via http')
        dispatchMethod = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_METHOD',
            'POST'
        ).upper()
        dispatchURL = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_URL',
            'https://localhost/'
        )
        logging.info(
            'Dispatching report via {method} to {url}'.format(
                method=dispatchMethod,
                url=dispatchURL
            )
        )
        try:
            r = requests.request(
                dispatchMethod,
                dispatchURL,
                json=report,
                headers={'Content-Type': 'application/json'}
            )
            r.raise_for_status()
            logging.info(
                "\tResponse Code: {status}\n\tResponse Data:\n{data}".format(
                    status=r.status_code,
                    data=r.text
                )
            )
        except requests.HTTPError as e:
            logging.error(
                "Dispatcher failed to deliver\n\tResponse Code: {status}\n\tResponse Data:\n{data}".format(
                    status=r.status_code,
                    data=r.text
                )
            )

class STDOUTDispatcher(object):
    def dispatch(self, report):
        logging.info('Dispatching report via stdout')
        if config.report == "plain":
            logging.info("\n{div}\n{report}".format(div="-" * 10, report=report))
        else:
            print(report)
