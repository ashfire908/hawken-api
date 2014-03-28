#!/user/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(name="hawkenapi",
      version="0.4",
      description="Hawken API Client Library",
      author="Andrew Hampe",
      author_email="andrew.hampe@gmail.com",
      packages=["hawkenapi", "hawkenapi.sleekxmpp"],
      install_requires=["requests", "enum34"],
      classifiers=(
          "Development Status :: 3 - Alpha",
          "Intended Audience :: Developers",
          "Natural Language :: English",
          "Programming Language :: Python :: 3.3"
      )
)
