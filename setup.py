#!/user/bin/env python
# -*- coding: utf-8 -*-

import sys
from distutils.core import setup

import hawkenapi

install_requires = ["requests", "iso8601"]
if sys.version_info < (3, 4):
    install_requires.append("enum34")

setup(name="hawkenapi",
      version=hawkenapi.__version__,
      description="Hawken API Client Library",
      author="Andrew Hampe",
      author_email="andrew.hampe@gmail.com",
      packages=["hawkenapi", "hawkenapi.sleekxmpp"],
      install_requires=install_requires,
      extras_require={
          "Cache": ["msgpack-python", "redis"],
          "XMPP": ["sleekxmpp"]
      },
      classifiers=(
          "Development Status :: 4 - Beta",
          "Intended Audience :: Developers",
          "Natural Language :: English",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6"
      )
)
