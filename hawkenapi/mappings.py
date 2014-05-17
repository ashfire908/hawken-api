# -*- coding: utf-8 -*-
# API mappings
# Copyright (c) 2013-2014 Andrew Hampe

from enum import IntEnum


class MatchState(IntEnum):
    unavailable = 0
    prematch = 1
    inprogress = 2
    postmatch = 3
