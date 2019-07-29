from os.path import basename
import glob

def get_py_files(path):
    for py_file in glob.glob("{}*.py".format(path)):
        if not py_file.endswith("__init__.py"):
            yield basename(py_file)[:-3]

def install_static_imports(path):
    with open("{}__init__.py".format(path), 'w') as init_f:
        for pf in get_py_files(path):
            init_f.write("from .{} import *\n".format(pf))

install_static_imports("src/modules/discovery/")
install_static_imports("src/modules/hunting/")
install_static_imports("src/modules/report/")
install_static_imports("plugins/")
