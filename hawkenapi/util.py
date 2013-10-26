# -*- coding: utf-8 -*-
# Utilities


def enum(**enums):
    return type('Enum', (), enums)
