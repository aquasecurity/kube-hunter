from os.path import dirname, basename, isfile
import glob

from .common import *  # noqa

# dynamically importing all modules in folder
files = glob.glob(dirname(__file__) + "/*.py")
for module_name in (basename(f)[:-3] for f in files if isfile(f) and not f.endswith("__init__.py")):
    if module_name != "handler":
        exec("from .{} import *".format(module_name))
