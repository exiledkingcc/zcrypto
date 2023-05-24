# code: utf-8

import os
import pathlib
from distutils.core import setup, Extension

name = "zcrypto"
ver = "0.1"

pydir = pathlib.Path(os.path.abspath(__file__)).parent
rootdir = pydir.parent
inc_dir = rootdir / "include"
src_dir = rootdir / "src"
src = [pydir / "ext.c", src_dir / "sm3.c", src_dir / "sm4.c"]
src = [str(x) for x in src]

setup(
    name = name,
	version = ver,
	ext_modules = [Extension(name, src, include_dirs=[inc_dir])]
)
