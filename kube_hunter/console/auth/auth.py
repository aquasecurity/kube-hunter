import cmd2

class AuthSubConsole(cmd2.Cmd):
    def __init__(self, env):
        self.env = env
        self.prompt = environment.get_prompt(sub_console="env/auth")

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
            
            print(environment.current_auth.get_auth(auth_index).raw_token)
        else:
            print(environment.current_auth.get_table())
    
    def do_exit(self, arg):
        return True

    def postcmd(self, stop, line):
        self.prompt = self.prompt.get_prompt(sub_console="env/auth")
        if stop:
            return True

    def emptyline(self):
         pass
