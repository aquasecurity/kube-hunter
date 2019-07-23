import json
import logging
import os
import urllib3
from urllib3.exceptions import HTTPError


class HTTPDispatcher(object):
    def dispatch(self, report):
        logging.error('Dispatching report via http')
        http = urllib3.PoolManager()
        encoded_data = json.dumps(report).encode('utf-8')
        dispatchMethod = os.environ.get(
            'KUBEHUNTER_DISPATCH_METHOD',
            'POST'
        ).upper()
        dispatchURL = os.environ.get(
            'KUBEHUNTER_DISPATCH_URL',
            'https://localhost/'
        )
        logging.debug(
            'Dispatching report via {method} to {url}'.format(
                method=dispatchMethod,
                url=dispatchURL
            )
        )
        try:
            r = http.request(
                dispatchMethod,
                dispatchURL,
                body=encoded_data,
                headers={'Content-Type': 'application/json'}
            )
            logging.debug(
                "\tResponse Code: {status}\n\tResponse Data:\n{data}".format(
                    status=r.status,
                    data=r.data.decode("utf-8")
                )
            )
        except HTTPError as e:
            logging.error(
                "Dispatcher failed to deliver\n\tResponse Code: {status}\n\tResponse Data:\n{data}".format(
                    status=r.status,
                    data=r.data.decode("utf-8")
                )
            )

