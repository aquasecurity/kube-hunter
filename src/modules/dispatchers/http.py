import logging
import os
import requests


class HTTPDispatcher(object):
    def dispatch(self, report):
        logging.error('Dispatching report via http')
        dispatchMethod = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_METHOD',
            'POST'
        ).upper()
        dispatchURL = os.environ.get(
            'KUBEHUNTER_HTTP_DISPATCH_URL',
            'https://localhost/'
        )
        logging.debug(
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
            logging.debug(
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

