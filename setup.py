#!/user/bin/env python
# -*- coding: utf-8 -*-

from distutils.core import setup

setup(name="HawkenApi",
      version="0.1.2",
      description="Hawken API Client Library",
      author="Andrew Hampe",
      author_email="andrew.hampe@gmail.com",
      packages=["hawkenapi", "hawkenapi.sleekxmpp"],
      classifiers=(
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'Natural Language :: English',
          'Programming Language :: Python :: 3.3'
          )
      )
