import cmd
import logging

from kube_hunter.console.env import environment
from kube_hunter.console.discover import DiscoverSubConsole
from kube_hunter.console.show import ShowSubConsole

from kube_hunter.modules.discovery.hosts import RunningAsPodEvent


def start_console():
    KubeHunterMainConsole().cmdloop()

class KubeHunterMainConsole(cmd.Cmd):
    kube_hunter_logo = r"""
 __              __                     __                     __                  
/\ \            /\ \                   /\ \                   /\ \__               
\ \ \/'\   __  _\ \ \____    __        \ \ \___   __  __   ___\ \ ,_\    __  _ __  
 \ \ , <  /\ \/\ \ \ '__`\ /'__`\ ______\ \  _ `\/\ \/\ \/' _ `\ \ \/  /'__`/\`'__\ 
  \ \ \\`\\ \ \_\ \ \ \L\ /\  __//\______\ \ \ \ \ \ \_\ /\ \/\ \ \ \_/\  __\ \ \/ 
   \ \_\ \_\ \____/\ \_,__\ \____\/______/\ \_\ \_\ \____\ \_\ \_\ \__\ \____\ \_\ 
    \/_/\/_/\/___/  \/___/ \/____/         \/_/\/_/\/___/ \/_/\/_/\/__/\/____/\/_/ 
    """
    intro = f'{kube_hunter_logo}\n\nWelcome to kube-hunter Immeresed Console. Type help or ? to list commands.\n'
    prompt = environment.get_prompt()

    discover_cmd = DiscoverSubConsole()
    show_cmd = ShowSubConsole()

    def do_show(self, arg):
        'Show your environment data collected so far'
        self.show_cmd.cmdloop()

    def do_discover(self, arg):
        'Depends on your environment, lets you discover nearby Services/Pods/Clusters'
        self.discover_cmd.cmdloop()

    def do_hunt(self, arg):
        'Depends on your environment, lets you hunt nearby Services/Pods/Clusters'
        pass
        
    def do_interactive(self, arg):
        import ipdb
        ipdb.set_trace()

    def do_whereami(self, arg):
        """Try to determine you are based on local files and mounts"""
        pod_event = RunningAsPodEvent()
        if pod_event.auth_token:
            environment.current_pod.incluster_update(pod_event)
            environment.current_auth.new_auth(pod_event.auth_token)
            environment.is_inside_pod = True

    def postcmd(self, stop, line):
        self.prompt = environment.get_prompt()

    def do_exit(self, arg):
        'exists shell'
        return True
    
    def emptyline(self):
         pass
    
    # binds EOF to exit the shell as well
    do_EOF = do_exit

