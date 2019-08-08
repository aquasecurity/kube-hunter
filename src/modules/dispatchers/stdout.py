import logging
from __main__ import config


class STDOUTDispatcher(object):
    def dispatch(self, report):
        logging.info('Dispatching report via stdout')
        if config.report == "plain":
            logging.info("\n{div}\n{report}".format(div="-" * 10, report=report))
        else:
            print(report)
