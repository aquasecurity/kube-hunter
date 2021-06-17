import json
import base64

from prettytable import PrettyTable, ALL

""" Auth models"""
class Auth:
    def parse_token(self, token):
        """ Extracting data from token file """
        # adding maximum base64 padding to parse correctly
        self.raw_token = token
        token_json = base64.b64decode(f"{token.split('.')[1]}==")
        token_data = json.loads(token_json)
        
        self.iss = token_data.get("iss")
        self.namespace = token_data.get("kubernetes.io/serviceaccount/namespace")
        self.name = token_data.get("kubernetes.io/serviceaccount/secret.name")
        self.service_account_name = token_data.get("kubernetes.io/serviceaccount/service-account.name")
        self.uid = token_data.get("kubernetes.io/serviceaccount/service-account.uid")
        self.sub = token_data.get("sub")

    def __init__(self, token=None):
        if token:
            self.parse_token(token)    

class AuthStore:
    auths = []
    selected_auth = None

    def new_auth(self, token):
        """ Initializes new Auth object and adds it to the auth db """
        new_auth = Auth(token)
        
        if not self.is_exists(new_auth):
            self.auths.append(new_auth)

            # if it's the only auth, selecting it
            if not self.selected_auth:
                self.selected_auth = 0
    
    def get_auths_count(self):
        return len(self.auths)

    def delete_auth(self, index):
        return self.auths.pop(index) 

    def is_exists(self, check_auth):
        """ Checks for uniques auth in auth_store """
        for auth in self.auths:
            if auth.sub == check_auth.sub:
                return True
        return False

    def get_current_auth(self):
        return self.auths[self.selected_auth]

    def get_auth(self, index):
        return self.auths[index]

    def set_select_auth(self, index):
        self.selected_auth = index
        
    def get_table(self):
        auth_table = PrettyTable(["index", "Name", "Selected"], hrules=ALL)
        auth_table.align = "l"
        auth_table.padding_width = 1
        auth_table.header_style = "upper"
        
        # building auth token table, showing selected auths
        for i, auth in enumerate(self.auths):
            selected_mark = ""
            if i == self.selected_auth:
                selected_mark = "*"
            auth_table.add_row([i, auth.sub, selected_mark])
        
        return auth_table