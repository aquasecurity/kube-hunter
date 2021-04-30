import cmd

from kube_hunter.console.env import environment
from kube_hunter.console.models import Container
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

    def do_discover(self, arg):
        'Depends on your environment, lets you discover nearby Services/Pods/Clusters'
        pass
    # ----- basic commands -----
    def do_exit(self, arg):
        'Depends on your environment, lets you discover nearby Services/Pods/Clusters'
        return True

    def postcmd(self, stop, line):
        self.prompt = environment.get_prompt()
