# -*- coding: utf-8 -*-
# Copyright (c) 2013-2014 Andrew Hampe

from sleekxmpp.plugins.base import register_plugin
from hawkenapi.sleekxmpp.base import Hawken
from hawkenapi.sleekxmpp.party import Hawken_Party


register_plugin(Hawken)
register_plugin(Hawken_Party)
