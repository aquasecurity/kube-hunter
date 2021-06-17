from kube_hunter.console.general import BaseKubeHunterCmd

class AuthSubConsole(BaseKubeHunterCmd):
    def __init__(self, env):
        super(AuthSubConsole, self).__init__()
        self.env = env
        self.sub_console_name = "env/auth"

    def do_set(self, auth_index):
        """Manages the auth database, Usage: 
        auth + = <auth_token> // adds a new auth 
        auth 0 = <auth_token> // edits an already set auth index
        """
        pass

    def do_show(self, auth_index):
        """Show current collected auths"""
        if auth_index:
            try: 
                auth_index = int(auth_index)
            except:
                print("ERROR: Auth index should be a integer")
                return
            
            print(self.env.current_auth.get_auth(auth_index).raw_token)
        else:
            print(self.env.current_auth.get_table())
