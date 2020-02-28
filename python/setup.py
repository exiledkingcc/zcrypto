# code: utf-8

import os
from distutils.core import setup, Extension

name = "zcrypto"
ver = "0.1"

pydir = os.path.dirname(os.path.abspath(__file__))
rootdir = os.path.dirname(pydir)
libdir = os.path.join(rootdir, name)
src = ["../{}/{}".format(name, x) for x in os.listdir(libdir) if x.endswith(".c")]
src.extend([x for x in os.listdir(pydir) if x.endswith(".c")])
print(src)

setup(
    name = name,
	version = ver,
	ext_modules = [Extension(name, src, include_dirs=[rootdir])]
)
