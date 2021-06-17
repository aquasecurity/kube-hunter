import cmd2

class BaseKubeHunterCmd(cmd2.Cmd):
    sub_console_name = ""

    def postcmd(self, stop, line):
        self.prompt = self.env.get_prompt(self.sub_console_name)
        if stop:
            return True
    
    def do_exit(self, arg):
        'exists shell'
        return True
    
    def emptyline(self):
         pass