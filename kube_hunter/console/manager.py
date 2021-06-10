import cmd

from kube_hunter.console.env import environment
from kube_hunter.console.discover import DiscoverSubConsole

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
        discover_cmd = DiscoverSubConsole()
        discover_cmd.cmdloop()

    def do_hunt(self, arg):
        'Depends on your environment, lets you hunt nearby Services/Pods/Clusters'
        discover_cmd = DiscoverSubConsole()
        discover_cmd.cmdloop()

    def do_show(self, arg):
        pass

    def postcmd(self, stop, line):
        self.prompt = environment.get_prompt()

    # def do_help(self, arg):
    #     if not arg:
    #         pass

    def do_exit(self, arg):
        'exists shell'
        return True

    # binds EOF to exit the shell as well
    do_EOF = do_exit

