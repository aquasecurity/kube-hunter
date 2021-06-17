from kube_hunter.console.general import BaseKubeHunterCmd
from kube_hunter.console.env import EnvSubConsole, ImmersedEnvironment
from kube_hunter.modules.discovery.hosts import RunningAsPodEvent

class KubeHunterMainConsole(BaseKubeHunterCmd):
    def __init__(self, env):
        super(KubeHunterMainConsole, self).__init__()
        kube_hunter_logo = r"""
    __              __                     __                     __                  
    /\ \            /\ \                   /\ \                   /\ \__               
    \ \ \/'\   __  _\ \ \____    __        \ \ \___   __  __   ___\ \ ,_\    __  _ __  
    \ \ , <  /\ \/\ \ \ '__`\ /'__`\ ______\ \  _ `\/\ \/\ \/' _ `\ \ \/  /'__`/\`'__\ 
    \ \ \\`\\ \ \_\ \ \ \L\ /\  __//\______\ \ \ \ \ \ \_\ /\ \/\ \ \ \_/\  __\ \ \/ 
    \ \_\ \_\ \____/\ \_,__\ \____\/______/\ \_\ \_\ \____\ \_\ \_\ \__\ \____\ \_\ 
        \/_/\/_/\/___/  \/___/ \/____/         \/_/\/_/\/___/ \/_/\/_/\/__/\/____/\/_/ 
        """
        self.intro = f'{kube_hunter_logo}\n\nWelcome to kube-hunter Immeresed Console. Type help or ? to list commands.\n'
        self.env = env
        
    def do_env(self, arg):
        'Show your environment data collected so far'
        EnvSubConsole(self.env).cmdloop()
        
    def do_interactive(self, arg):
        """Start interactive ipython session"""
        environment = self.env
        self.poutput("\n\tStarted an interactive python session. use `environment` to manage the populated environment object")
        import ipdb
        ipdb.set_trace()

    def do_whereami(self, arg):
        """Try to determine you are based on local files and mounts"""
        pod_event = RunningAsPodEvent()
        if pod_event.auth_token:
            self.env.current_auth.new_auth(pod_event.auth_token)
            self.env.current_pod.incluster_update(pod_event)
            self.env.is_inside_pod = True


def start_console():
    environment = ImmersedEnvironment()
    a = KubeHunterMainConsole(environment)
    a.cmdloop()
