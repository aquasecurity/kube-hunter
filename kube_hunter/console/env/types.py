from colorama import init, Fore, Style

from kube_hunter.console.general import types as GeneralTypes
from kube_hunter.console.auth import types as AuthTypes

# initializes colorma
init()

class ImmersedEnvironment:
    """
    ImmersedEnvironment keeps track of the current console run state.
    """
    auths = []
    pods = []

    is_inside_cloud = False
    is_inside_container = False
    is_inside_pod = False

    current_cloud = GeneralTypes.UnknownCloud()
    current_pod = GeneralTypes.Pod()
    current_container = GeneralTypes.Container()
    
    current_auth = AuthTypes.AuthStore()

    def get_prompt(self, sub_console=""):
        """
        Parses current env state to picture a short description of where we are right now
        General format is `(cloud) -> (run_unit) kube-hunter $`
        """
        arrow = "->"
        prompt_prefix = f" kube-hunter{' [' + sub_console + ']' if sub_console else ''} $ "

        # add colores unly
        cloud = f"({Fore.BLUE}{self.current_cloud}{Style.RESET_ALL})"
        pod = f"({Fore.MAGENTA}{self.current_pod}{Style.RESET_ALL})"
        container = f"(container: {Fore.CYAN}{self.current_container}{Style.RESET_ALL})"
        container_in_pod = f"({Fore.MAGENTA}{self.current_pod}/{{}}{Style.RESET_ALL})"

        env_description = ""
        if self.current_auth.get_auths_count():
            auth =  self.current_auth.get_current_auth()
            env_description += f"  {Fore.LIGHTRED_EX}[Impersonating {auth.sub}]{Style.RESET_ALL}\n"

        env_description += cloud
        if self.is_inside_pod:
            if len(self.current_pod.containers):
                env_description += f" {arrow} {container_in_pod.format(self.current_pod.containers[0])}"
            else:
                env_description += f" {arrow} {pod}"

        elif self.is_inside_container:
            env_description += f" {arrow} {container}"

        return f"{env_description}{prompt_prefix}"
