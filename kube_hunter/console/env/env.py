import cmd2

from kube_hunter.console.auth import AuthSubConsole


class EnvSubConsole(cmd2.Cmd):
    """EnvSubConsole
    In charge of managing and viewing the entire current environment state
    Includes: Auth database..
    """
    def __init__(self, env):
        super(EnvSubConsole, self).__init__()
        self.env = env
        self.prompt = self.env.get_prompt(sub_command="env")

    def do_auth(self, arg):
        AuthSubConsole(self.env).cmdloop() 

    def postcmd(self, stop, line):
        self.prompt = self.env.get_prompt(sub_command="env")
        if stop:
            return True
    
    def do_exit(self, arg):
        'exists shell'
        return True
    
    def emptyline(self):
         pass
    
    # binds EOF to exit the shell as well
    do_EOF = do_exit
