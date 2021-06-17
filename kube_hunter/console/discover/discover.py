from kube_hunter.console.auth import AuthSubConsole
from kube_hunter.console.general import BaseKubeHunterCmd

from kube_hunter.conf import Config, set_config
from kube_hunter.conf.logging import setup_logger
from kube_hunter.core.events import handler
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent, HostScanEvent
from kube_hunter.modules.report import get_reporter, get_dispatcher
from kube_hunter.core.events.types import HuntFinished, HuntStarted

import time
from cmd2 import ansi
from progressbar import FormatLabel, RotatingMarker, UnknownLength, ProgressBar, Timer

class HuntSubConsole(BaseKubeHunterCmd):
    """DiscoverSubConsole
    In charge of managing and running kube-hunter's discover modules
    """
    def __init__(self, env):
        super(HuntSubConsole, self).__init__()
        self.env = env
        self.sub_console_name = "hunt"
    
    @staticmethod
    def progress_bar():
        """Displays animated progress bar
        Integrates with handler object, to properly block until hunt finish
        """
        # Logger 
        widgets = ['[', Timer(), ']', ': ', FormatLabel(''), ' ',  RotatingMarker()]
        bar = ProgressBar(max_value=UnknownLength, widgets=widgets)
        while handler.unfinished_tasks > 0:
            widgets[4] = FormatLabel(f'Tasks Left To Process: {handler.unfinished_tasks}')
            bar.update(handler.unfinished_tasks)
            time.sleep(0.1)
        bar.finish()

    def do_everything(self, arg):
        """Wraps running of kube-hunter's hunting
        Uses the current environment to specify data to start_event when starting a scan
        """
        # TODO: display output
        current_auth = self.env.current_auth.get_current_auth()
        
        start_event = None
        if self.env.is_inside_pod:
            self.pfeedback(ansi.style(f"Hunting Started (as {current_auth.sub})", fg="green"))
            
            start_event = RunningAsPodEvent()
            start_event.auth_token = current_auth.raw_token
            
        # setting basic stuff for output methods
        setup_logger("none", None)
        config = Config()
        config.dispatcher = get_dispatcher("stdout")
        config.reporter = get_reporter("plain")
        set_config(config)

        # trigger hunting
        handler.publish_event(start_event)
        handler.publish_event(HuntStarted())

        self.progress_bar()
        self.pfeedback(ansi.style(f"Finished hunting. found {0} services and {0} vulnerabilities", fg="green"))
        handler.join()