# -*- coding: utf-8 -*-

from enum import IntEnum


class MatchState(IntEnum):
    unavailable = 0
    prematch = 1
    inprogress = 2
    postmatch = 3
