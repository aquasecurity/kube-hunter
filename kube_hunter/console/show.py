import cmd
import logging

from kube_hunter.console.env import environment

class ShowSubConsole(cmd.Cmd):
    prompt = environment.get_prompt(sub_console="show")

    def do_auth(self, auth_index):
        """Displays the auth database, to show raw data of an auth entry pass it's index as a parameter."""
        if auth_index:
            try: 
                auth_index = int(auth_index)
            except:
                print("ERROR: Auth index should be a number")
                return
            
            print(environment.current_auth.get_auth(auth_index).raw_token)
        else:
            print(environment.current_auth.__repr__())

    def do_exit(self, arg):
        return True

    def postcmd(self, stop, line):
        self.prompt = environment.get_prompt(sub_console="show")
        if stop:
            return True

    def emptyline(self):
         pass
    
    # binds EOF to exit the shell as well
    do_EOF = do_exit