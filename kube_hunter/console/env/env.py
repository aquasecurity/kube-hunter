from kube_hunter.console.auth import AuthSubConsole
from kube_hunter.console.general import BaseKubeHunterCmd

class EnvSubConsole(BaseKubeHunterCmd):
    """EnvSubConsole
    In charge of managing and viewing the entire current environment state
    Includes: Auth database..
    """
    def __init__(self, env):
        super(EnvSubConsole, self).__init__()
        self.env = env
        self.sub_console_name = "env"
        # self.prompt = self.env.get_prompt(sub_console="env")

    def do_auth(self, arg):
        AuthSubConsole(self.env).cmdloop()

