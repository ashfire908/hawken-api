# -*- coding: utf-8 -*-

from hawkenapi.util import enum

MatchState = enum(UNAVAILABLE=0, PREMATCH=1, INPROGRESS=2, POSTMATCH=3)
