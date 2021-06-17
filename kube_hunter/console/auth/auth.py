import argparse
from cmd2 import with_argparser
from kube_hunter.console.general import BaseKubeHunterCmd


class AuthSubConsole(BaseKubeHunterCmd):
    """
    Manages the underlying AuthStore database
    Implementes 3 methods to manage the db
    
    delete - Removes an auth entry by an index
    create - creates a new entry in the db, 
    select - select the auth to use in the environment
    """
    def __init__(self, env):
        super(AuthSubConsole, self).__init__()
        self.env = env
        self.sub_console_name = "env/auth"

    delete_parser = argparse.ArgumentParser()
    delete_parser.add_argument("index", type=int, help="index of the auth entry for deletion")
    @with_argparser(delete_parser)
    def do_delete(self, opts):
        """Creates a new entry in the auth database based on a given raw jwt token"""
        if opts.index:
            if self.env.current_auth.get_auths_count() > opts.index:
                self.env.current_auth.delete_auth(opts.jwt_token.strip())
            else:
                self.perror("Index too large")

    create_parser = argparse.ArgumentParser()
    create_parser.add_argument("jwt_token", help="A raw jwt_token of the new auth entry")
    @with_argparser(create_parser)
    def do_create(self, opts):
        """Creates a new entry in the auth database based on a given raw jwt token"""
        if opts.jwt_token:
            self.env.current_auth.new_auth(opts.jwt_token.strip())
    
    
    show_parser = argparse.ArgumentParser()
    show_parser.add_argument("-i", "--index", type=int, help="set index to print raw data for a specific auth entry")
    @with_argparser(show_parser)
    def do_show(self, opts):
        """Show current collected auths"""
        if opts.index is not None:
            if self.env.current_auth.get_auths_count() > opts.index:
                self.poutput(f"Token:\n{self.env.current_auth.get_auth(opts.index).raw_token}")
            else:
                self.perror("Index too large")
        else:
            self.poutput(self.env.current_auth.get_table())
