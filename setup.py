from configparser import ConfigParser
from pkg_resources import parse_requirements
from subprocess import check_call
from typing import Any, List
from setuptools import setup, Command


class ListDependenciesCommand(Command):
    """A custom command to list dependencies"""

    description = "list package dependencies"
    user_options: List[Any] = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        cfg = ConfigParser()
        cfg.read("setup.cfg")
        requirements = cfg["options"]["install_requires"]
        print(requirements)


class PyInstallerCommand(Command):
    """A custom command to run PyInstaller to build standalone executable."""

    description = "run PyInstaller on kube-hunter entrypoint"
    user_options: List[Any] = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        cfg = ConfigParser()
        cfg.read("setup.cfg")
        command = [
            "pyinstaller",
            "--additional-hooks-dir",
            "pyinstaller_hooks",
            "--clean",
            "--onefile",
            "--name",
            "kube-hunter",
        ]
        setup_cfg = cfg["options"]["install_requires"]
        requirements = parse_requirements(setup_cfg)
        for r in requirements:
            command.extend(["--hidden-import", r.key])
        command.append("kube_hunter/__main__.py")
        print(" ".join(command))
        check_call(command)


setup(
    use_scm_version={"fallback_version": "noversion"},
    cmdclass={"dependencies": ListDependenciesCommand, "pyinstaller": PyInstallerCommand},
)
