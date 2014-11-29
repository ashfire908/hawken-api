#!/user/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(name="hawkenapi",
      version="0.6.1.3",
      description="Hawken API Client Library",
      author="Andrew Hampe",
      author_email="andrew.hampe@gmail.com",
      packages=["hawkenapi", "hawkenapi.sleekxmpp"],
      install_requires=["requests", "enum34"],
      extras_require={
          "Cache": ["msgpack-python", "redis"],
          "XMPP": ["sleekxmpp"]
      },
      classifiers=(
          "Development Status :: 3 - Alpha",
          "Intended Audience :: Developers",
          "Natural Language :: English",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4"
      )
)
