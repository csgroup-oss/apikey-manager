# sources :
# https://medium.com/swlh/distributing-python-packages-protected-with-cython-40fc29d84caf
# https://medium.com/@xpl/protecting-python-sources-using-cython-dcd940bb188e

import os
import sysconfig

from Cython.Build import cythonize
from setuptools import find_packages, setup
from setuptools.command.build_py import build_py as _build_py

EXCLUDE_FILES = ["./build.py"]


class build_py(_build_py):
    def find_package_modules(self, package, package_dir):
        ext_suffix = sysconfig.get_config_var("EXT_SUFFIX")
        modules = super().find_package_modules(package, package_dir)
        filtered_modules = []
        for pkg, mod, filepath in modules:
            if os.path.exists(filepath.replace(".py", ext_suffix)):
                continue
            filtered_modules.append(
                (
                    pkg,
                    mod,
                    filepath,
                )
            )
        return filtered_modules


def get_ext_paths(root_dir, exclude_files):
    """get filepaths for compilation"""
    paths = []
    for root, _, files in os.walk(root_dir):
        for filename in files:
            if os.path.splitext(filename)[1] != ".py":
                continue
            file_path = os.path.join(root, filename)
            if file_path in exclude_files:
                continue
            paths.append(file_path)
    return paths


setup(
    name="apikeymanager",
    version="1.0.0",
    packages=find_packages(),
    ext_modules=cythonize(
        get_ext_paths("app/", EXCLUDE_FILES), compiler_directives={"language_level": 3}
    ),
    cmdclass={"build_py": build_py},
)
